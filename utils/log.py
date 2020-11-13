from models.device import Device


class Logger():
    def __init__(self, device: Device):
        self.device = device

    def prepare_message(self, *messages):
        msgs = []
        for m in messages:
            msgs.append(m[0])
        return " ".join(msgs)

    def ilog(self, *messages):
        print(self.device.get_device_id(), self.prepare_message(messages))

    def elog(self, *messages):
        print(self.device.get_device_id(), self.prepare_message(messages))

    def exception(self, file, method, exception):
        print(file, method.__name__, str(exception))
