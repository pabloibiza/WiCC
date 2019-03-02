class Client:
    id = ""
    station_MAC = ""
    first_seen = ""
    last_seen = ""
    power = 0
    packets = 0
    bssid = ""
    probed_bssids = ""

    def __init__(self,id,station_MAC,first_seen,last_seen,power,packets,bssid,probed_bssids):
        self.id = id
        self.station_MAC = station_MAC
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.power = power
        self.bssid = bssid
        self.probed_bssids = probed_bssids

    '''
        Pending to implement __str__ and getters and setters
        For prototype 2
    '''
