from conversation import Conversation


class EncryptedConversation(Conversation):
    def setup_conversation(self):
        pass

    def process_incoming_message(self, msg_raw, msg_id, owner_str):
        pass

    def process_outgoing_message(self, msg_raw, originates_from_console=False):
        pass
