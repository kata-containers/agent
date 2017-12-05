TARGET = kata-agent

$(TARGET):
	go build -o $@

.PHONY: clean
clean:
	rm -f $(TARGET)
