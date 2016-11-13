from conversation import Conversation


class EncryptedConversation(Conversation):
    def setup_conversation(self):
        # if role is initiator, generate a group key, encrypt it and save it.

        # if responder, send a nonce to the server to request a group key

        pass

    def process_incoming_message(self, msg_raw, msg_id, owner_str):
        # message format = (sequence number, sender, encrypted content, purpose, digital signature)
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

        # ignore other situations

        pass

    def process_outgoing_message(self, msg_raw, originates_from_console=False):
        # if message purpose is new message
        #     1) Encrypt the message using the group key
        #     2) Attach the digital signature
        #     3) Attach a sequence number

        # ignore other situations
        pass
