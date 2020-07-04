class PortFilter:
 
    def __init__(self, ip, port):
        self.ip = ip
        self.ports = []
        self.checkPort(port)
 
    def getPortList(self):
        return self.ports
 
    def getPortListLenght(self):
        return len(self.ports)
 
    def checkPort(self,port):
        if port not in self.ports:
            self.ports.append(port)
 
    def getIP(self):
        return self.ip