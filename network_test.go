//
// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/kata-containers/agent/pkg/types"
	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestUpdateRemoveInterface(t *testing.T) {
	skipUnlessRoot(t)

	s := sandbox{}

	ifc := types.Interface{
		Name:   "enoNumber",
		Mtu:    1500,
		HwAddr: "02:00:ca:fe:00:48",
	}
	ip := types.IPAddress{
		Family:  0,
		Address: "192.168.0.101",
		Mask:    "24",
	}
	ifc.IPAddresses = append(ifc.IPAddresses, &ip)

	netHandle, _ := netlink.NewHandle()
	defer netHandle.Delete()

	//
	// Initial test: try to update a device which doens't exist:
	//
	_, err := s.updateInterface(netHandle, &ifc)
	assert.NotNil(t, err, "Expected to observe interface couldn't be found error")

	// create a dummy link that we can test update on
	macAddr := net.HardwareAddr{0x02, 0x00, 0xCA, 0xFE, 0x00, 0x48}
	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			MTU:          1500,
			TxQLen:       -1,
			Name:         "ifc-name",
			HardwareAddr: macAddr,
		},
	}
	netHandle.LinkAdd(link)
	netHandle.LinkSetUp(link)

	//
	// With a link populated, check to see if we can successfully update:
	//
	resultingIfc, err := s.updateInterface(netHandle, &ifc)
	assert.Nil(t, err, "Unexpected update interface failure: %v", err)
	assert.True(t, reflect.DeepEqual(resultingIfc, &ifc),
		"Interface created didn't match: got %+v, expecting %+v", resultingIfc, ifc)

	// Try with a different valid MTU.  Make sure we can assign a new set of IP addresses
	ifc.Mtu = 500
	ifc.IPAddresses[0].Address = "192.168.0.102"
	ip2 := types.IPAddress{
		Family:  0,
		Address: "182.168.0.103",
		Mask:    "24",
	}
	ifc.IPAddresses = append(ifc.IPAddresses, &ip2)

	resultingIfc, err = s.updateInterface(netHandle, &ifc)
	assert.Nil(t, err, "Unexpected update interface failure: %v", err)
	assert.True(t, reflect.DeepEqual(resultingIfc, &ifc),
		"Interface created didn't match: got %+v, expecting %+v", resultingIfc, ifc)

	// Try with garbage:
	ifc.Mtu = 999999999999
	resultingIfc, err = s.updateInterface(netHandle, &ifc)
	// expecting this failed
	assert.NotNil(t, err, "Expected failure")

	ifc.Mtu = 500
	assert.True(t, reflect.DeepEqual(resultingIfc, &ifc),
		"Resulting inteface should have been unchanged: got %+v, expecting %+v", resultingIfc, ifc)

	// Exercise the removeInterface code:
	_, err = s.removeInterface(netHandle, &ifc)
	assert.Nil(t, err, "remove interface failed: %v", err)

	// Try to remove non existent interface:
	_, err = s.removeInterface(netHandle, &ifc)
	assert.NotNil(t, err, "Expected failed removal: %v", err)
}

type teardownNetworkTest func()

func setupNetworkTest(t *testing.T) teardownNetworkTest {
	skipUnlessRoot(t)

	// new temporary namespace so we don't pollute the host
	// lock thread since the namespace is thread local
	runtime.LockOSThread()
	var err error
	ns, err := netns.New()
	if err != nil {
		t.Fatal("Failed to create newns", ns)
	}

	return func() {
		ns.Close()
		runtime.UnlockOSThread()
	}
}

func TestUpdateRoutes(t *testing.T) {
	tearDown := setupNetworkTest(t)
	defer tearDown()

	s := sandbox{}

	// create a dummy link which we'll play with
	macAddr := net.HardwareAddr{0x02, 0x00, 0xCA, 0xFE, 0x00, 0x48}
	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			MTU:          1500,
			TxQLen:       -1,
			Name:         "ifc-name",
			HardwareAddr: macAddr,
		},
	}
	netHandle, _ := netlink.NewHandle()
	defer netHandle.Delete()

	netHandle.LinkAdd(link)
	if err := netHandle.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	netlinkAddr, _ := netlink.ParseAddr("192.168.0.2/16")
	netHandle.AddrAdd(link, netlinkAddr)

	//Test a simple route setup:
	inputRoutesSimple := []*types.Route{
		{Dest: "", Gateway: "192.168.0.1", Source: "", Scope: 0, Device: "ifc-name"},
		{Dest: "192.168.0.0/16", Gateway: "", Source: "192.168.0.2", Scope: 253, Device: "ifc-name"},
	}

	testRoutes := &pb.Routes{
		Routes: inputRoutesSimple,
	}

	results, err := s.updateRoutes(netHandle, testRoutes)
	assert.Nil(t, err, "Unexpected update interface failure: %v", err)
	assert.True(t, reflect.DeepEqual(results, testRoutes),
		"Interface created didn't match: got %+v, expecting %+v", results, testRoutes)

	//Test a route setup mimicking what could be provided by PTP CNI plugin:
	inputRoutesPTPExample := []*types.Route{
		{Dest: "", Gateway: "192.168.0.1", Source: "", Scope: 0, Device: "ifc-name"},
		{Dest: "192.168.0.144/16", Gateway: "192.168.0.1", Source: "192.168.0.2", Scope: 0, Device: "ifc-name"},
		{Dest: "192.168.0.1/32", Gateway: "", Source: "192.168.0.2", Scope: 254, Device: "ifc-name"},
	}
	testRoutes.Routes = inputRoutesPTPExample

	results, err = s.updateRoutes(netHandle, testRoutes)
	assert.Nil(t, err, "Unexpected update interface failure: %v", err)
	assert.True(t, reflect.DeepEqual(results, testRoutes),
		"Interface created didn't match: got %+v, expecting %+v", results, testRoutes)

	//Test unreachable example (no scope provided for initial link route)
	inputRoutesNoScope := []*types.Route{
		{Dest: "", Gateway: "192.168.0.1", Source: "", Scope: 0, Device: "ifc-name"},
		{Dest: "192.168.0.0/16", Gateway: "", Source: "192.168.0.2", Scope: 0, Device: "ifc-name"},
	}
	testRoutes.Routes = inputRoutesNoScope
	results, err = s.updateRoutes(netHandle, testRoutes)
	assert.NotNil(t, err, "Expected to observe unreachable route failure")

	assert.True(t, reflect.DeepEqual(results.Routes[0], testRoutes.Routes[1]),
		"Interface created didn't match: got %+v, expecting %+v", results.Routes[0], testRoutes.Routes[1])
}

func TestUpdateRoutesIPVlan(t *testing.T) {
	tearDown := setupNetworkTest(t)
	defer tearDown()

	s := sandbox{}
	testRoutes := &pb.Routes{}

	// create a dummy link which we'll play with
	macAddr := net.HardwareAddr{0x02, 0x00, 0xCA, 0xFE, 0x00, 0x48}
	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			MTU:          1500,
			TxQLen:       -1,
			Name:         "ifc-name",
			HardwareAddr: macAddr,
		},
	}
	netHandle, _ := netlink.NewHandle()
	defer netHandle.Delete()

	netHandle.LinkAdd(link)
	if err := netHandle.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	netlinkAddr, _ := netlink.ParseAddr("192.168.0.2/16")
	netHandle.AddrAdd(link, netlinkAddr)

	//Test a route setup mimicking what could be provided by ipvlan CNI plugin:
	inputRoutesIPVlanExample := []*types.Route{
		// route "default dev ifc-name scope link"
		{Dest: "", Gateway: "", Source: "", Scope: 1, Device: "ifc-name"},

		// route "192.168.0.0/24 dev eth0 proto kernel scope link src 192.168.0.2"
		// TODO : We dont really handle route protocol currently. We need to add this and
		// test that protocol is handled.
		// Issue: https://github.com/kata-containers/agent/issues/405
		{Dest: "192.168.0.0/24", Gateway: "", Source: "192.168.0.2", Scope: 1, Device: "ifc-name"},
	}
	testRoutes.Routes = inputRoutesIPVlanExample

	results, err := s.updateRoutes(netHandle, testRoutes)
	assert.Nil(t, err, "Unexpected update interface failure: %v", err)
	assert.True(t, reflect.DeepEqual(results, testRoutes),
		"Interface created didn't match: got %+v, expecting %+v", results, testRoutes)

}

func TestListInterfaces(t *testing.T) {
	tearDown := setupNetworkTest(t)
	defer tearDown()

	assert := assert.New(t)

	s := sandbox{}
	ifc := types.Interface{
		Name:   "enoNumber",
		Mtu:    1500,
		HwAddr: "02:00:ca:fe:00:48",
	}
	ip := types.IPAddress{
		Family:  0,
		Address: "192.168.0.101",
		Mask:    "24",
	}
	ifc.IPAddresses = append(ifc.IPAddresses, &ip)
	netHandle, _ := netlink.NewHandle()
	defer netHandle.Delete()
	// create a dummy link that we can test update on
	macAddr := net.HardwareAddr{0x02, 0x00, 0xCA, 0xFE, 0x00, 0x48}
	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			MTU:          1500,
			TxQLen:       -1,
			Name:         "ifc-name",
			HardwareAddr: macAddr,
		},
	}
	netHandle.LinkAdd(link)
	netHandle.LinkSetUp(link)
	s.updateInterface(netHandle, &ifc)
	//
	// With a link populated, check to see if we can successfully list:
	//
	results, err := s.listInterfaces(nil)
	assert.Nil(err, "Expected to list all interfaces")
	assert.True(reflect.DeepEqual(results.Interfaces[1], &ifc),
		"Interface listed didn't match: got %+v, expecting %+v", results.Interfaces[1], &ifc)
}

func TestListRoutes(t *testing.T) {
	tearDown := setupNetworkTest(t)
	defer tearDown()

	assert := assert.New(t)

	s := sandbox{}

	// create a dummy link which we'll play with
	macAddr := net.HardwareAddr{0x02, 0x00, 0xCA, 0xFE, 0x00, 0x48}
	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			MTU:          1500,
			TxQLen:       -1,
			Name:         "ifc-name",
			HardwareAddr: macAddr,
		},
	}
	netHandle, _ := netlink.NewHandle()
	defer netHandle.Delete()

	netHandle.LinkAdd(link)
	if err := netHandle.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	netlinkAddr, _ := netlink.ParseAddr("192.168.0.2/16")
	netHandle.AddrAdd(link, netlinkAddr)

	//Test a simple route setup:
	inputRoutesSimple := []*types.Route{
		{Dest: "", Gateway: "192.168.0.1", Source: "", Scope: 0, Device: "ifc-name"},
	}

	expectedRoutes := []*types.Route{
		{Dest: "", Gateway: "192.168.0.1", Source: "", Scope: 0, Device: "ifc-name"},
		// This route is auto-added by kernel, and we no longer delete kernel proto routes
		{Dest: "192.168.0.0/16", Gateway: "", Source: "192.168.0.2", Scope: 253, Device: "ifc-name"},
	}

	testRoutes := &pb.Routes{
		Routes: inputRoutesSimple,
	}

	_, err := s.updateRoutes(netHandle, testRoutes)
	assert.Nil(err)
	results, err := s.listRoutes(nil)
	assert.Nil(err, "Expected to list all routes")

	assert.True(reflect.DeepEqual(results.Routes[0], expectedRoutes[0]),
		"Route listed didn't match: got %+v, expecting %+v", results.Routes[0], expectedRoutes[0])
	assert.True(reflect.DeepEqual(results.Routes[1], expectedRoutes[1]),
		"Route listed didn't match: got %+v, expecting %+v", results.Routes[1], expectedRoutes[1])

	inputRoutesSimple = []*types.Route{
		{Dest: "", Gateway: "192.168.0.1", Source: "", Scope: 0, Device: "ifc-name"},
		// This works too, in case a duplicate route added by kernel exists, this route will over-ride it
		{Dest: "192.168.0.0/16", Gateway: "", Source: "192.168.0.2", Scope: 253, Device: "ifc-name"},
	}

	testRoutes = &pb.Routes{
		Routes: inputRoutesSimple,
	}

	_, err = s.updateRoutes(netHandle, testRoutes)
	assert.Nil(err)
	results, err = s.listRoutes(nil)
	assert.Nil(err, "Expected to list all routes")

	assert.True(reflect.DeepEqual(results.Routes[0], inputRoutesSimple[0]),
		"Route listed didn't match: got %+v, expecting %+v", results.Routes[0], inputRoutesSimple[0])
	assert.True(reflect.DeepEqual(results.Routes[1], inputRoutesSimple[1]),
		"Route listed didn't match: got %+v, expecting %+v", results.Routes[1], inputRoutesSimple[1])
}

func TestListRoutesWithTwoInterfacesSameSubnet(t *testing.T) {
	tearDown := setupNetworkTest(t)
	defer tearDown()

	assert := assert.New(t)

	s := sandbox{}

	// create a dummy link which we'll play with
	macAddr := net.HardwareAddr{0x02, 0x00, 0xCA, 0xFE, 0x00, 0x48}
	linkOne := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			MTU:          1500,
			TxQLen:       -1,
			Name:         "ifc-name",
			HardwareAddr: macAddr,
		},
	}
	netHandle, _ := netlink.NewHandle()
	defer netHandle.Delete()

	netHandle.LinkAdd(linkOne)
	if err := netHandle.LinkSetUp(linkOne); err != nil {
		t.Fatal(err)
	}
	netlinkAddr, _ := netlink.ParseAddr("192.168.0.2/16")
	netHandle.AddrAdd(linkOne, netlinkAddr)

	linkTwo := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			MTU:          1500,
			TxQLen:       -1,
			Name:         "ifc-name2",
			HardwareAddr: macAddr,
		},
	}

	netHandle.LinkAdd(linkTwo)
	if err := netHandle.LinkSetUp(linkTwo); err != nil {
		t.Fatal(err)
	}
	netlinkAddr, _ = netlink.ParseAddr("192.168.0.3/16")
	netHandle.AddrAdd(linkTwo, netlinkAddr)

	//Test a simple route setup:
	inputRoutesSimple := []*types.Route{
		{Dest: "", Gateway: "192.168.0.1", Source: "", Scope: 0, Device: "ifc-name"},
	}

	expectedRoutes := []*types.Route{
		{Dest: "", Gateway: "192.168.0.1", Source: "", Scope: 0, Device: "ifc-name"},
		{Dest: "192.168.0.0/16", Gateway: "", Source: "192.168.0.2", Scope: 253, Device: "ifc-name"},
		{Dest: "192.168.0.0/16", Gateway: "", Source: "192.168.0.3", Scope: 253, Device: "ifc-name2"},
	}

	testRoutes := &pb.Routes{
		Routes: inputRoutesSimple,
	}

	_, err := s.updateRoutes(netHandle, testRoutes)
	assert.Nil(err)
	results, err := s.listRoutes(nil)
	assert.Nil(err, "Expected to list all routes")

	assert.True(reflect.DeepEqual(results.Routes[0], expectedRoutes[0]),
		"Route listed didn't match: got %+v, expecting %+v", results.Routes[0], expectedRoutes[0])
	assert.True(reflect.DeepEqual(results.Routes[1], expectedRoutes[1]),
		"Route listed didn't match: got %+v, expecting %+v", results.Routes[1], expectedRoutes[1])
	assert.True(reflect.DeepEqual(results.Routes[2], expectedRoutes[2]),
		"Route listed didn't match: got %+v, expecting %+v", results.Routes[2], expectedRoutes[2])

}

// As mounting errors out in permission denied, so test kataGuestSandboxDNSFile contents only.
func TestSetupDNS(t *testing.T) {
	skipUnlessRoot(t)

	tmpfile, err := ioutil.TempFile("", "resolv.conf")
	assert.NoError(t, err)
	guestDNSFile = tmpfile.Name()

	tmpfile, err = ioutil.TempFile("", "resolv.conf")
	assert.NoError(t, err)
	kataGuestSandboxDNSFile = tmpfile.Name()

	defer os.RemoveAll(guestDNSFile)
	defer os.RemoveAll(kataGuestSandboxDNSFile)

	dns := []string{
		"nameserver 8.8.8.8",
		"nameserver 8.8.4.4",
	}

	err = setupDNS(dns)
	assert.NoError(t, err)

	content, err := ioutil.ReadFile(guestDNSFile)
	assert.NoError(t, err)

	expectedDNS := strings.Split(string(content), "\n")
	assert.Equal(t, dns, expectedDNS)
}
