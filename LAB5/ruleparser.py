# -----------------------------------START OF RULE PARSER CLASS --------------------------------------
class RuleParser():
    #the constructor
    def __init__(self,rulefilename):
        self.rulefilename = rulefilename
        #to store all the valid rules
        self.rules = []


    def start(self):
        #reading the lines from the given rule filename
        with open(self.rulefilename) as f:
            lines = f.readlines()
            #the curr line number
            curr_line_num = 0
            #total number of lines in rule filename
            total_lines = len(lines)
            #to count the number of rules parsed
            total_rules = 0
            #to count the number of valid rules
            total_valid_rules = 0

            while(curr_line_num < total_lines):
                #to determine the start of the rule
                if(lines[curr_line_num].strip() == 'BEGIN'):
                    total_rules += 1
                    curr_line_num += 1
                    new_rule = {}
                    valid = True
                    #parsing the new rule
                    while(True):
                        #to determine the end of the rule
                        if (lines[curr_line_num].strip() == 'END'):
                            #if the rule is valid then store the rule else not store
                            if valid:
                                total_valid_rules += 1
                                self.rules.append(new_rule)
                            curr_line_num += 1
                            break
                        
                        line = lines[curr_line_num].strip()
                        #getting the key and value pair for each of the lines in rule
                        key,value = line.split(":")
                        #to strip space from the begining and end of the value
                        value = value.strip()

                        #based on the key doing appropriate actions
                        if(key == 'NUM'):
                            new_rule["id"] = value

                        elif key == 'SRC IP ADDR':
                            new_rule["src ip addr"] = value

                        elif key == 'DEST IP ADDR':
                            new_rule["dest ip addr"] = value

                        elif key == 'SRC PORT':
                            start,end = value.split('-')
                            start,end = int(start),int(end)

                            if start == 0 and end == 0:
                                start = 1
                                end = 65535
                            new_rule["src port"] = {"start" : start,"end": end}
                            if start > end or start < 1 or end > 65535:
                                valid = False

                        elif key == 'DEST PORT':
                            start,end = value.split('-')
                            start,end = int(start),int(end)
                            
                            if start == 0 and end == 0:
                                start = 1
                                end = 65535
                            new_rule["dest port"] = {"start" : start,"end": end}
                            if start > end or start < 1 or end > 65535:
                                valid = False

                        elif key == 'PROTOCOL':
                            new_rule["protocol"] = value

                        elif key == 'DATA':
                            new_rule["data"] = value
                        else:
                            valid = False

                        curr_line_num += 1
                        
        #storing the number of total rules and the number of vlaid rules      
        self.total_rules = total_rules
        self.total_valid_rules = total_valid_rules       

    #method to get the information of the rules,number of rules and number of valid rules
    def get_info(self):
        return self.rules,self.total_rules,self.total_valid_rules

# -----------------------------------------END OF CLASS -------------------------


