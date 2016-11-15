import base64
from message import Message
from Crypto.Cipher import AES
from Crypto import Random
from encrypted_message import EncryptedMessage
from base64 import b64encode
from conversation import Conversation
from config import *


class EncryptedConversation(Conversation):
    def setup_conversation(self):
        list_of_users = self.manager.get_active_user_for_current_conversation()
        print list_of_users
        # if no one in chat room, generate a group key, encrypt it and save it.
        if list_of_users == [self.manager.user_name]:
            key = Random.new().read(AES.key_size[1])
            self.group_key = key
            self.key_exchange_state = KEY_EXCHANGE_DONE
            print "Generate group key: " + self.group_key
        # if there exists a client in chat room, send a nonce to the server to request a group key
        else:
            encoded_msg = base64.encodestring(EncryptedMessage.format_message(list_of_users[0], REQUEST_KEY))
            # post the message to the conversation
            self.manager.post_key_exchange_message(encoded_msg)

    def process_incoming_message(self, msg_raw, msg_id, owner_str):
        # message format = (sequence number, owner, encrypted content, purpose, digital signature)
        # if key exchange done and message purpose is new message:
        #     1) verify sender's identity by checking the digital signature
        #     2) Check whether the sequence number is valid
        #     3) decrypt the message using its private RSA key and get the group key

        # if key exchange is not done and message purpose is receive key,
        #     1) Verify sender's identity by checking the digital signature
        #     4) Decrypt the message and check whether the nonce is valid
        #     2) Save the group key
        #     3) Decrypt message history and print it

        # if key exchange done and message purpose is request key:
        #     1) Check whether the digital signature is valid
        #     2) Encrypt the nonce and the group key using the sender's public RSA key, and send it to the server
        decoded_msg = base64.decodestring(msg_raw)
        message = EncryptedMessage.decode_message(decoded_msg)
        if message["purpose"] == REQUEST_KEY and self.key_exchange_state == KEY_EXCHANGE_DONE and message["content"] == self.manager.user_name:
            encoded_msg = base64.encodestring(EncryptedMessage.format_message(self.group_key, SEND_KEY))
            # post the message to the conversation
            self.manager.post_key_exchange_message(encoded_msg)
        elif message["purpose"] == SEND_KEY and self.key_exchange_state == KEY_EXCHANGE_NOT_DONE:
            self.group_key = message["content"]
            self.key_exchange_state = KEY_EXCHANGE_DONE
        else:
            # print message and add it to the list of printed messages
            self.print_message(
                msg_raw=decoded_msg,
                owner_str=owner_str
            )

    def process_outgoing_message(self, msg_raw, originates_from_console=False):
        # if message purpose is new message
        #     1) Encrypt the message using the group key
        #     2) Attach the digital signature
        #     3) Attach the owner
        #     4) Attach a sequence number
        #     5) Attach the purpose

        # ignore other situations
        if originates_from_console == True:
            # message is already seen on the console
            m = Message(
                owner_name=self.manager.user_name,
                content=msg_raw
            )
            self.printed_messages.append(m)

            # process outgoing message here
        # example is base64 encoding, extend this with any crypto processing of your protocol
        encoded_msg = base64.encodestring(msg_raw)

        # post the message to the conversation
        self.manager.post_message_to_conversation(encoded_msg)
