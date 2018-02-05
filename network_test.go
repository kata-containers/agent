//
// Copyright (c) 2017 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"net"
	"reflect"
	"testing"

	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

func TestUpdateRemoveInterface(t *testing.T) {

	s := sandbox{}

	ifc := pb.Interface{
		Name:   "enoNumber",
		Mtu:    1500,
		HwAddr: "02:00:ca:fe:00:48",
	}
	ip := pb.IPAddress{
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
	ip2 := pb.IPAddress{0, "182.168.0.103", "24"}
	ifc.IPAddresses = append(ifc.IPAddresses, &ip2)

	resultingIfc, err = s.updateInterface(netHandle, &ifc)
	assert.Nil(t, err, "Unexpected update interface failure: %v", err)
	assert.True(t, reflect.DeepEqual(resultingIfc, &ifc),
		"Interface created didn't match: got %+v, expecting %+v", resultingIfc, ifc)

	// Try with garbage:
	//
	ifc.Mtu = 999999999999
	resultingIfc, err = s.updateInterface(netHandle, &ifc)
	// expecting this failed
	assert.NotNil(t, err, "Expected failure")

	ifc.Mtu = 500
	assert.True(t, reflect.DeepEqual(resultingIfc, &ifc),
		"Resulting inteface should have been unchanged: got %+v, expecting %+v", resultingIfc, ifc)

	//
	// Test adding routes:
	//
	route := pb.Route{
		Dest:    "192.168.3.0/24",
		Gateway: "192.168.0.1",
		Device:  "enoNumber",
	}
	err = s.addRoute(netHandle, &route)
	assert.Nil(t, err, "add route failed: %v", err)

	//
	// Test remove routes:
	//
	err = s.removeRoute(netHandle, &route)
	assert.Nil(t, err, "remove route failed: %v", err)

	//
	// Exercise the removeInterface code:
	//
	_, err = s.removeInterface(netHandle, &ifc)
	assert.Nil(t, err, "remove interface failed: %v", err)

	// Try to remove non existent interface:
	_, err = s.removeInterface(netHandle, &ifc)
	assert.NotNil(t, err, "Expected failed removal: %v", err)
}
