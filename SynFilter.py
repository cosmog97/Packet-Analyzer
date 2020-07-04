class SynFilter:
 
    def __init__(self, threshold):
        self.threshold = threshold
        self.syn_count = 0
        self.synack_count = 0
        self.ack_count = 0

    def incrementSyn(self):
        self.syn_count += 1

    def incrementSynAck(self):
        self.synack_count += 1

    def incrementAck(self):
        self.ack_count += 1 

    def getSynAckCount(self):
        return self.synack_count

    def getAckCount(self):
        return self.ack_count

    def getSynCount(self):
        return self.syn_count

    def valuateSynFlood(self):
        mean = (self.synack_count + self.ack_count)/2
        if self.syn_count > (mean + self.threshold):
            return True
        return False