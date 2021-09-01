import ipaddress
import time
# --------------------------------START OF PACKET PARSER CLASS ----------------------------
class PktParserAndMatcher():
# --------------------------------------CONSTRUCTOR ------------------------------------
    #constructor
    def __init__(self,pktfilename,rules):
        self.pktfilename = pktfilename
        self.packets = []
        self.rules = rules
# --------------------START OF PACKET READING METHOD ---------------------------------------
    #reads all the packets from the packet file
    def readPackets(self):

        #reading the lines from the given packet filename
        with open(self.pktfilename) as f:
            lines = f.readlines()
            #the curr line number
            curr_line_num = 0
            #total number of lines in packet file
            total_lines = len(lines)
           

            while(curr_line_num < total_lines):
                #to determine the start of the packet
                if(lines[curr_line_num].strip() == 'BEGIN'):
    
                    curr_line_num += 1
                    new_pkt = {}
                    
                    #parsing the new packet
                    while(True):
                        #to determine the end of the packet
                        if (lines[curr_line_num].strip() == 'END'):
    
                            self.packets.append(new_pkt)
                            curr_line_num += 1
                            break
                        
                        line = lines[curr_line_num].strip()
                        #getting the key and value pair for each of the lines in packet
                        key,value = line.split(":")
                        #to strip space from the begining and end of the value
                        value = value.strip()

                        #based on the key doing appropriate actions
                        if(key == 'NUM'):
                            new_pkt["id"] = int(value)

                        elif key == 'SRC IP ADDR':
                            new_pkt["src ip addr"] = value

                        elif key == 'DEST IP ADDR':
                            new_pkt["dest ip addr"] = value

                        elif key == 'SRC PORT':
                            new_pkt['src port'] = int(value)

                        elif key == 'DEST PORT':
                           new_pkt['dest port'] = int(value)

                        elif key == 'PROTOCOL':
                            new_pkt["protocol"] = value

                        elif key == 'DATA':
                            new_pkt["data"] = value
                        else:
                            print("wrong format")

                        curr_line_num += 1

        self.total_packets = len(self.packets)
    # ------------------------------END OF PACKET PARSING METHOD ------------------------------
    # ---------------------------------START OF PACKET VALIDATION METHOD --------------------------
     #to check if the packets are valid or not   
    def _checkValidPacket(self,packet):
        #if the ports are not in the range then the packets are not valid
        if packet["src port"] < 0 or packet['src port'] > 65535:
            return False
        
        if packet['dest port'] < 0 or packet['dest port'] > 65535:
            return False

        return True
# ------------------------------END OF PACKET VALIDATION METHOD ------------------------------------
# -----------------------------START OF PACKET MATCHING METHOD -----------------------------------------
    def matchPackets(self):
        valid_packets = 0
        total_time_taken = 0
        #parsing packets one by one
        for packet in self.packets:
            #checking if the packet is valid or not
            if not self._checkValidPacket(packet):
                print("Packet number {} is invalid.".format(packet["id"]))
                continue
                
            matched_rules_id = []
            valid_packets += 1
            #to count the secs passed while matching the packet with the rules
            begin = time.time()
            #if valid packet then one by one checking if the packet matches the rule
            for rule in self.rules:
                # if ip address not in the range then the rule does not match, hence move onto the next rule
                if ipaddress.IPv4Address(packet["src ip addr"]) not in ipaddress.IPv4Network(rule["src ip addr"]):
                    continue
                if ipaddress.IPv4Address(packet["dest ip addr"]) not in ipaddress.IPv4Network(rule["dest ip addr"]):
                    continue
                #to check if the port are in the range of the rule or not
                if not (packet["src port"] >= rule["src port"]["start"] and packet["src port"] <= rule["src port"]["end"]):
                    continue
                if not (packet["dest port"] >= rule["dest port"]["start"] and packet["dest port"] <= rule["dest port"]["end"]):
                    continue
                #to check if the protocol matches or not
                if packet["protocol"] != rule["protocol"]:
                    continue
                #to check if the payload data of the rule is present in the packet or not
                if rule["data"] != '*' and rule["data"] not in packet["data"]:
                    continue
                #if all the things matches then the packet matches with the rule
                #storing the matched rule id
                matched_rules_id.append(rule["id"])
            
            end = time.time()
            #the time taken for matching of the packets with the rules
            total_time_taken += (end - begin)
            #printing the results i.e the rules which matched that particular packet
            if len(matched_rules_id) > 0:
                rules_list = ",".join(matched_rules_id)
                print("Packet number {} matches {} rule(s): {}.".format(packet["id"],len(matched_rules_id),rules_list))
            else:
                print("Packet number {} matches no rule.".format(packet["id"]))

        #print the final result   
        print("A total of {} packet(s) were read from the file and processed. Bye.".format(self.total_packets))
        print("Average time taken per packet: {} milliseconds".format(total_time_taken*1e3/valid_packets))
    # -------------------------------END OF PACKET MATCHING METHOD -------------------------------------------
    #----------------------------------END OF CLASS ----------------------------------------------------------