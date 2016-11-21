import base64
from message import Message
from Crypto.Cipher import AES
from Crypto import Random
from encrypted_message import EncryptedMessage
from base64 import b64encode
from base64 import b64decode
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
from conversation import Conversation
from config import *
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import random
import time


class EncryptedConversation(Conversation):
    def generate_nonce(self,length=8):
        return ''.join([str(random.randint(0, 9)) for i in range(length)])

    def handle_key_exchange_message(self, message):
        result = {}
        result["key"] = message[-AES.key_size[1]:]
        rest = message[:-AES.key_size[1]].split("|")
        result["user"] = base64.decodestring(rest[0])
        result["sender"] = base64.decodestring(rest[1])
        result["nonce"] = rest[2]
        print result
        return result

    def setup_conversation(self):
        # Acquire active_user_list and all the public keys of every participants in the conversation
        info = self.manager.get_active_user_for_current_conversation()
        list_of_users = info["user_list"]
        self.users_public_key = info["user_info"]
        for i in self.users_public_key.keys():
            self.sequence_numbers[i] = 0
        # if no one in chat room, generate a group key, encrypt it and save it.
        if list_of_users == [self.manager.user_name]:
            key = Random.new().read(AES.key_size[1])
            self.group_key = key
            self.key_exchange_state = KEY_EXCHANGE_DONE
            print "Generate group key: " + self.group_key
        # if there exists a client in chat room, send a nonce to the server to request a group key
        else:
            self.nonce_sent_time = time.time()
            print "Generating nonce: " + str(self.nonce_sent_time)
            self.nonce = self.generate_nonce(8)
            encoded_msg = base64.encodestring(
                EncryptedMessage.format_message(self.nonce, REQUEST_KEY, list_of_users[0]))
            # post the message to the conversation
            self.manager.post_key_exchange_message(encoded_msg)

    def process_incoming_message(self, msg_raw, msg_id, owner_str):
        # message format = (sequence number, owner, encrypted content, purpose, digital signature, receiver)
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

        # decode message
        decoded_msg = base64.decodestring(msg_raw)
        message = EncryptedMessage.decode_message(decoded_msg)

        # handle key request message
        if message["purpose"] == REQUEST_KEY and self.key_exchange_state == KEY_EXCHANGE_DONE and message[
            "receiver"] == self.manager.user_name:
            # encode the group key in public key of the owner
            pubkey = RSA.importKey(self.users_public_key[owner_str])
            cipher = PKCS1_OAEP.new(pubkey)
            key_exchange_message = base64.encodestring(owner_str) + "|" + base64.encodestring(self.manager.user_name) + "|" + str(message[
                "content"]) + "|" + self.group_key
            print "Sending key exchange message: " + key_exchange_message
            encrypted_group_key = cipher.encrypt(key_exchange_message)
            # compute the digital signature
            signature = self.compute_signature(encrypted_group_key)
            # send the message to the owner
            encoded_msg = base64.encodestring(
                EncryptedMessage.format_message(encrypted_group_key, SEND_KEY, owner_str, signature))
            self.manager.post_key_exchange_message(encoded_msg)

        # handle message containing group key
        elif message["purpose"] == SEND_KEY and self.key_exchange_state == KEY_EXCHANGE_NOT_DONE and message[
            "receiver"] == self.manager.user_name:
            # check the digital signature
            if self.check_signature(message, self.users_public_key[owner_str]):
                cipher = PKCS1_OAEP.new(self.manager.private_key)
                decrypted_message = cipher.decrypt(message["content"])
                received_message = self.handle_key_exchange_message(decrypted_message)
                # check whether the nonce is valid
                if received_message["sender"] == owner_str and received_message["user"] ==  self.manager.user_name and time.time()-self.nonce_sent_time < 15 and received_message["nonce"] == str(self.nonce):
                    print time.time()-self.nonce_sent_time
                    self.group_key = received_message["key"]
                    print "Receive group key: " + self.group_key
                    self.key_exchange_state = KEY_EXCHANGE_DONE
                    # process all the message stored in the history
                    for i in self.message_history:
                        self.process_incoming_message(i[0], i[1], i[2])
                else:
                    print "Key Exchange Failed"
                    self.request_key()
            else:
                self.request_key()
        # if key exchange is not done, save the message to history
        elif message[
            "purpose"] == MESSAGE and owner_str != self.manager.user_name and self.key_exchange_state == KEY_EXCHANGE_NOT_DONE:
            self.message_history.append([msg_raw, msg_id, owner_str])
        # process the message if key exchange is done
        elif message[
            "purpose"] == MESSAGE and owner_str != self.manager.user_name and self.key_exchange_state == KEY_EXCHANGE_DONE:
            # check whether the sequence number is valid
            # add error checking
            if message["sequence_number"] > self.sequence_numbers[owner_str]:
                print "Receiving message with sequence number: " + str(
                    message["sequence_number"]) + " by owner: " + owner_str
                self.sequence_numbers[owner_str] += 1
                # check whether signature is valid
                if self.check_signature(message, self.users_public_key[owner_str]):
                    # print message and add it to the list of printed messages
                    self.print_message(
                        msg_raw=self.cbc_decode(message["content"]),
                        owner_str=owner_str
                    )

    def request_key(self):
        # post another message to request the key
        encoded_msg = base64.encodestring(
            EncryptedMessage.format_message("", REQUEST_KEY,
                                            self.manager.get_active_user_for_current_conversation()[
                                                "user_list"][0]))
        self.manager.post_key_exchange_message(encoded_msg)

    def check_signature(self, message, public_key):
        pubkey = RSA.importKey(public_key)
        h = SHA.new()
        h.update(message["content"])
        verifier = PKCS1_PSS.new(pubkey)
        if verifier.verify(h, b64decode(message["signature"])):
            return True
        return False

    def compute_signature(self, message):
        h = SHA.new()
        h.update(message)
        signer = PKCS1_PSS.new(self.manager.private_key)
        signature = b64encode(signer.sign(h))
        return signature

    def process_outgoing_message(self, msg_raw, originates_from_console=False):
        # if message purpose is new message
        #     1) Encrypt the message using the group key (done)
        #     2) Attach the digital signature (done)
        #     3) Attach the owner (done)
        #     4) Attach a sequence number
        #     5) Attach the purpose (done)

        # ignore other situations

        # example is base64 encoding, extend this with any crypto processing of your protocol
        msg_raw = self.cbc_encode(msg_raw)
        signature = self.compute_signature(msg_raw)
        # compute the sequence number
        self.sequence_numbers[self.manager.user_name] += 1
        sequence_number = self.sequence_numbers[self.manager.user_name]
        print "Sending out message with sequence number: " + str(
            sequence_number) + " by owner: " + self.manager.user_name
        message = EncryptedMessage.format_message(msg_raw, MESSAGE, "", signature, sequence_number)
        message = base64.encodestring(message)
        if originates_from_console == True or message["purpose"] == SEND_KEY or message["purpose"] == REQUEST_KEY:
            # message is already seen on the console
            m = Message(
                owner_name=self.manager.user_name,
                content=message
            )
            self.printed_messages.append(m)

            # process outgoing message here

        # post the message to the conversation
        self.manager.post_message_to_conversation(message)

    def cbc_encode(self, msg_raw):
        # TLS style padding
        plength = AES.block_size - (len(msg_raw) % AES.block_size)
        msg_raw += chr(plength) * plength

        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.group_key, AES.MODE_CBC, iv)

        return b64encode(iv + cipher.encrypt(msg_raw))

    def cbc_decode(self, msg):
        msg = b64decode(msg)
        iv = msg[:AES.block_size]
        msg = msg[AES.block_size:]
        cipher = AES.new(self.group_key, AES.MODE_CBC, iv)
        msg = cipher.decrypt(msg)
        # remove padding
        msg = msg[:len(msg) - ord(msg[-1])]
        return msg
