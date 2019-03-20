class Client:
    client_id = ""
    station_MAC = ""
    first_seen = ""
    last_seen = ""
    power = 0
    packets = 0
    bssid = ""
    probed_bssids = ""

    def __init__(self, id, station_MAC, first_seen, last_seen, power, packets, bssid, probed_bssids):
        self.client_id = id
        self.station_MAC = station_MAC
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.power = power
        self.packets = packets
        self.bssid = bssid
        self.probed_bssids = probed_bssids

    def get_bssid(self):
        return self.bssid

    def get_mac(self):
        return self.station_MAC

    def get_list(self):
        list = []
        list.append(self.client_id)
        list.append(self.station_MAC)
        list.append(self.first_seen)
        list.append(self.first_seen)
        list.append(self.last_seen)
        list.append(self.power)
        list.append(self.power)
        list.append(self.packets)
        list.append(self.bssid)
        list.append(self.probed_bssids)

        return list

    '''
        Pending to implement __str__ and getters and setters
        For prototype 2
    '''
