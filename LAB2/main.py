import sys
import CREATEKEYS
import READMAIL
import CREATEMAIL



if __name__ == "__main__":

    #gets the command line arguments
    arg = sys.argv

    #arg[0] is the name of the python file

    if arg[1] == "CreateKeys":
        #collecting all the arguments so that it can used to perform the following command
        user_name_list = arg[2]
        RSA_keysize = int(arg[3])
        result = CREATEKEYS.create_keys(user_name_list,RSA_keysize)
        #printing the result success or some failure
        print(result)

    elif arg[1] == "CreateMail":
        #collecting all the arguments so that it can used to perform the following command
        sec_type = arg[2]
        sender = arg[3]
        receiver = arg[4]
        email_input_file = arg[5]
        email_output_file = arg[6]
        digest_algo = arg[7]
        encry_alg = arg[8]
        RSA_keysize = int(arg[9])
        result = CREATEMAIL.create_mail(sec_type,sender,receiver,email_input_file,email_output_file,digest_algo,encry_alg,RSA_keysize)
        #printing the result success or some failure
        print(result)

    elif arg[1] == "ReadMail":  
        #collecting all the arguments so that it can used to perform the following command
        sec_type = arg[2]
        sender = arg[3]
        receiver = arg[4]
        secure_input_file = arg[5]
        plain_output_file = arg[6]
        digest_algo = arg[7]
        encry_alg = arg[8]
        RSA_keysize = int(arg[9])
        result = READMAIL.read_mail(sec_type,sender,receiver,secure_input_file,plain_output_file,digest_algo,encry_alg,RSA_keysize)
        #printing the result success or some failure
        print(result)
    else:

        print("ERROR!!! WRONG FORAMT")
    



