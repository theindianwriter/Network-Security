
import sys
from ruleparser import RuleParser
from pktparser import PktParserAndMatcher



def main():
    #parse the arguments from the command line
    args = sys.argv
    rulefilename = args[1]
    pktfilename = args[2]
    #creating an instance of the rule parser
    R = RuleParser(rulefilename)
    #parsing all the rules from the rulefilename
    R.start()
    #getting the set of valid rules from the info of the class
    rules,total_rules_parsed,total_valid_rules_found = R.get_info()
    print("A total of {} rules were read; {} valid rules are stored.".format(total_rules_parsed,total_valid_rules_found))

    #creaitng an instance of the packet traser and matcher
    P = PktParserAndMatcher(pktfilename,rules)
    #reading the packets
    P.readPackets()
    #matching the packets with the rules and displaying the results
    P.matchPackets()


if __name__ == '__main__':
    main()