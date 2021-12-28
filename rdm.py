"""
RDM module handles all operation related to the rdm protocol on DMX
What is RDM?
         Remote Device Management is a protocol that sits on top of the DMX data standard for lighting control.
         DMX is a unidirectional protocol which means that the data flows in one direction – from the controller(Desk or dmx512 usbpro) to the lights.
         With the addition of RDM, the DMX512 system becomes a bi-directional (half-duplex) system. The controller is able to send out a question to
         devices on the wire, which can then respond with an answer.
         The messages within the protocol cover all the everyday tasks a lighting system manager incurs – setting DMX addresses, modes and other configuration tasks, plus monitoring sensors, usage, status messages and fault finding.

         Think of an RDM transaction as a conversation – the lighting desk says ‘tell me your DMX address’ and the fixture responds with ‘my address is 32’.
         This is known as a GET command. Next the controller can send a SET command, such as ‘set your DMX address to 65’, and the fixture can respond to acknowledge this change.
         In this way, through GET and SET commands and responses, the RDM protocol allows a control desk to modify and monitor the DMX system in ways never possible before.
         source: https://www.rdmprotocol.org/

packet structrue:

        Start Code
        Sub Start Code
        Message Length
        Destination UID
        Source UID
        Transaction Number
        Port ID
        Message Count
        Sub Device:
        Command Class:
        Parameter ID:
        Parameter Data Length
        Parameter Data
        Checksum




"""
import time
import re
from binascii import hexlify
from serial import Serial


class UidsError(Exception):
    """
    Uids  Error class
    """
    message = None

    def __str__(self) -> str:
        return f"{self.message}"


class UidsNotFound(UidsError):
    """
    Raise when can't find any uids in response packet
    """
    message = "can't find any uids in response packet"


class InvalidCheckSum(UidsError):
    """
    Raise when discovry response packet checksum is invalid
    """
    message = "Destnation Uid is invalid"


class TimeOutError(UidsError):
    """
    Raise when it cannot fined any device
    after 1 min
    """
    message = "Timeout Error(cannot translate the responses)"


class Commands:
    """
    Data class contains all the
    RDM protocols commands
    """
    PROTOCOL_VERSION = 0x0100
    RDM_START = 0xcc
    SUB_START = 0x01
    RDM_HEADER_18 = 0x18
    RDM_HEADER_24 = 0x24
    # network
    DISC_MUTE = (0x00, 0x02)
    DISC_UNIQUE_BRANCH = (0x00, 0x01)
    DISC_UN_MUTE = (0x00, 0x03)
    BROAD_CAST = (0xFF, 0xFF, 0XFF, 0XFF, 0XFF, 0XFF)
    DISCOVERY = (0x00, 0x00, 0x00, 0x10)
    DISCOVERY_RESPONSE = (0x00, 0x00, 0x00, 0x11)
    GET = (0x00, 0x00, 0x00, 0x20)
    GET_RESPONSE = (0x00, 0x00, 0x00, 0x21)
    SET = (0x00, 0x00, 0x00, 0x30)
    SET_RESPONSE = (0x00, 0x00, 0x00, 0x31)
    # Responses
    RESPONSE_TYPE_ACK = 0x00
    RESPONSE_TYPE_ACK_TIMER = 0x01
    RESPONSE_TYPE_NACK_REASON = 0x02
    RESPONSE_TYPE_ACK_OVERFLOW = 0x03
    RESPONSE_DMX_ACK = b'~\x0c\x00\x00\xe7'
    # product info
    DEVICE_INFO = (0x00, 0x60)
    PRODUCT_DETAIL_ID_LIST = (0x00, 0x70)
    DEVICE_MODEL_DESCRIPTION = (0x00, 0x80)
    MANUFACTURER_LABEL = (0x00, 0x81)
    DEVICE_LABEL = (0x00, 0x82)


class UIDParser:
    """
    ParseUID class will parse and convert
    Device manufacture UID & device UID from
    RDM DISC_UNIQUE_BRANCH Response
    -> Package Encoding:
        byte(index)               data
        --------------------------------------------------------
          1                       0xfe
          2                       0xfe
          3                       0xfe
          4                       0xfe
          5                       0xfe
          6                       0xfe
          7                       0xfe
          8                       0xaa ---------> UIDS are after this byte
          9                       Manufactur ID1(MSB) OR with 0xaa
          10                      Manufactur ID1(MSB) OR with 0x55
          11                      Manufactur ID0(LSB) OR with 0xaa
          12                      Manufactur  ID1(LSB) OR with 0x55
          13                      Device ID3(MSB) OR with 0xaa
          14                      Device ID3(MSB) OR with 0x55
          15                      Device ID2 OR with 0xaa
          16                      Device ID2 OR with 0x55
          17                      Device ID1 OR with 0xaa
          18                      Device ID2 OR with 0x55
          19                      Device ID0(LSB) OR with 0xaa
          20                      Device ID1(MSB) OR with 0x55
          21                      Checksum1 (MSB) OR with 0xaa
          22                      Checksum1 (MSB) OR with 0x55
          23                      Checksum0 (LSB) OR with 0xaa
          24                      Checksum0 (LSB) OR with 0x55

    @methods
        decode()
        parse_uid()
        split_bytes()
        decode_bytes()
        decode_uids()


    """
    __slots__ = ()

    @classmethod
    def decode(cls, packet: bytes) -> tuple:
        """
        decode the given packet and return
        uids as tuple (class method )
        """

        return cls().decode_uids(packet)

    def parse_uid(self, packet: bytes) -> bytes:
        """
        Parse uid from the response packet.
        uids are after 0xfe0xaa bytes
        -> Params:
               packet: response packet
        <- return:
               parsed uid bytes
        """
        try:
            uids = re.findall(b'\xaa.+\xe7', packet)[0]
            return uids
        except IndexError:
            raise UidsNotFound

    def split_bytes(self, bytes_: bytearray) -> tuple:
        """
        Split the array of the byte 2 by 2
        and return 2 bytes as generator
        each next call will return (first, second)
        -> Params:
                 bytes
        <- return:
                generator
        """
        for index in range(1, len(bytes_), 2):
            yield tuple(bytes_[index: index+2])

    def decode_bytes(self, data: bytearray) -> int:
        """
        decode bytes from rdm response packet.
        response packet comes as an array of the bytes,
        for decoding we need to split the array into
        2 bytes 2 byes array then each 2 bytes must
        be masked with 0xaa and 0x55. first bytes of
        splited 2 bytes will be OR(logical opreators <|>) with 0xaa
        and second bytes with 0x55. then we AND(logical operator &)
        first and second byte to get the currect value.
        -> Params:
                 data: [2 bytes]
        <- Return
                return decoded value from bytes
        """
        try:
            first, second = data
        except ValueError:
            return 0
        # masking the bytes
        first |= 0xaa
        second |= 0x55
        return first & second

    def decode_uids(self, packet: bytearray) -> tuple:
        """
        Parse and decode the Uids from the response
        packet
        -> Params:
                packet: response packet
        <- Return:
                manufacturer&device uids, 3 element of
                tuple is manufacuret+device uids as hex
                (manufacturer_uid, device_uid, all_uids)
        """
        # parse the usable bytes from packet
        packet = self.parse_uid(packet)
        uids = [self.decode_bytes(bytes_)
                for bytes_ in self.split_bytes(packet)]
        mf_uid_index = slice(0, 2)
        device_uid_index = slice(2, 6)
        mf_uid = uids[mf_uid_index]
        device_uid = uids[device_uid_index]
        all_uids = bytes(uids[0:6])
        uid_checksum = uids[6:8]
        self._validate_uid(all_uids, uid_checksum)
        print(all_uids)
        return (mf_uid, device_uid, all_uids.hex())

    def _validate_uid(self, uids: list, uid_checksum: list) -> None:
        """
        validate checksum of the given uids.
        if last digit of uids is euqal converted
        check sum of the uids to 16bits is valid
        else it will raise invalid checksum
        -> Params:
               uids: list of uids
               check_sum: uids checksum
        """

        check_sum = PacketTools.calculate_checksum(uids)
        uid_checksum = sum(uid_checksum)
        if not uid_checksum == sum(check_sum):
            raise InvalidCheckSum


class PacketTools:
    """
    contains methods to convert or translate
    reqeust or response packets.
    @staticmethods
        translate_packets
        hex_view
        calculate_msb_lsb
        calculate_checksum
    """

    @staticmethod
    def translate_packets(packet: bytes) -> bytes:
        """
        trasnlate RDM/DMX reponse packets.
        first convert packet to an array then
        reverse array and convert it to bytes.
        second convert bytes from bytes to
        hex
        -> Params:
             packet: bytes

        <- Return:
             translate packet
        @example:
           input -> b'~\n\x04\x00H0$\x02\xe7'
           reponse: b'02243048'
        """
        packet = list(packet).__reversed__()
        translated_packet = hexlify(bytes(packet))
        return translated_packet

    @staticmethod
    def hex_view(packet: bytes) -> str:
        """
    Return packet as nicly formated
    hex vie 2x2 per bytes
    -> Params:
          packet
    <- Returns:
          formated packet
        """
        hex_packet = hexlify(packet).decode('ascii')
        hex_pair = ' '.join(hex_packet[i:i+2]
                            for i in range(0, len(hex_packet), 2))
        return hex_pair

    @staticmethod
    def calculate_msg_lsb(packet_length: int, offset: int = 255) -> tuple:
        """
        Calculate MSB(Must significant byte) and LSB(Least significant byte)
        base on packet length and the offset
        -> Params:
              packet_length
             offset: default 255
        <- return:
           (MSB, LSB)
        """
        msb = packet_length >> offset
        lsb = packet_length & offset
        return (msb, lsb)

    @staticmethod
    def calculate_checksum(packet: list, byte_order='big') -> list:
        """
        calculate checksum base on given packet.
        (sum elements + size of packet)
        -> Params:
                packet:list or tuple
                byte_order: default is big endianns
        <- Returns:
            calculated checksum as hex

        """
        # caclulate checksum
        total_packet_size = sum(packet)
        checksum_bytes = total_packet_size.to_bytes(
            length=2, byteorder=byte_order)
        return list(checksum_bytes)


class RemoteDeviceManagment:
    """
    RDM class handle all operation related
    to the RDM protocols
    -> Params:
          port: DMX controller port number
          buffer: reading buffer(default 50)
          timeout: read timeout (default 1 )
          disovery_timeout
    @methdos:
        create_header()
        get_device_serial()
        rdm_disc_branch_umute()
        rdm_discovery()
        rdm_mute_device()


    """
    DMX_START_BYTES = 0x7E
    DMX_END_BYTES = 0xE7
    WRITTEN_BYTES = 0
    PORT = 1
    PARAMETER_LENGTH = 12
    PARAMETER_DATA = (0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
    _transaction_number = 1

    def __init__(self, port: str, buffer: int = 50, timeout: int = 0.015,
                 discovery_timeout: int = 60) -> None:
        self.com = Serial(port, timeout=timeout)
        self.buffer = buffer
        self.device_serial = self.get_device_serial
        self._discovery_timeout = discovery_timeout

    def _execute(self, packet: list) -> bytes:
        """
        write given packet to com port and
        return response
        -> Params:
                packet: list or tuple
        """
        self.com.write(bytearray(packet))
        return self.com.read(self.buffer)

    def create_header(self, dmx_label: int, packet_length: int) -> tuple:
        """
        Create dmx header base on packet_length
        -> Params:
                 dmx-label: dmx label header
                            0x07 to 0x11 for reading the rmd
                            packet
                 packet_length: length of packet to calculate
                                LSM and MSB
        <- Returns:
                 tuple of header
                 (START_BYTE, RDM_LABEL, LSB, MSB)
        """
        msb, lsb = PacketTools.calculate_msg_lsb(packet_length)
        return (self.DMX_START_BYTES, dmx_label, lsb, msb)

    @property
    def get_device_serial(self) -> bytes:
        """
        Get dmx controller serial number.
        obtaining serial number is mandatory
        step before start sending rdm commands
        """
        serial_index = slice(4, 8)
        dmx_packet = (self.DMX_START_BYTES, 10, 2, 0, 0, 0,
                      self.DMX_END_BYTES)
        raw_serial = self._execute(dmx_packet)[serial_index]
        # changing bytes order
        raw_serial = bytearray(list(raw_serial).__reversed__())
        # add manufactory label Enttec
        raw_serial = b'EN' + raw_serial
        return raw_serial

    def rdm_disc_branch_umute(self) -> bytes:
        """
        Send RDM start packet or disc unmute
        this function can be used before starting
        the discovery to unmute all the devices
        """
        rmd_packet = (Commands.RDM_START,
                      Commands.SUB_START,
                      Commands.RDM_HEADER_18,
                      *Commands.BROAD_CAST,
                      *self.device_serial,
                      self._transaction_number,
                      self.PORT,
                      *Commands.DISCOVERY,
                      *Commands.DISC_UN_MUTE)

        check_sum = PacketTools.calculate_checksum(rmd_packet)
        packet_header = self.create_header(0x07, 26)
        packet = (*packet_header,
                  *rmd_packet,
                  self.WRITTEN_BYTES,
                  *check_sum, self.DMX_END_BYTES)
        response = self._execute(packet)
        return response

    def rdm_discovery(self) -> bytes:
        """
        Create and send discovery packet
        """
        self._transaction_number += 1
        rdm_packet = (Commands.RDM_START,
                      Commands.SUB_START,
                      Commands.RDM_HEADER_24,
                      *Commands.BROAD_CAST,
                      *self.device_serial,
                      self._transaction_number,
                      self.PORT,
                      *Commands.DISCOVERY,
                      *Commands.DISC_UNIQUE_BRANCH,
                      self.PARAMETER_LENGTH,
                      *self.PARAMETER_DATA)
        check_sum = PacketTools.calculate_checksum(rdm_packet)
        packet_header = self.create_header(0x0b, 38)
        packet = (*packet_header,
                  *rdm_packet,
                  *check_sum,
                  self.DMX_END_BYTES)
        response = self._execute(packet)
        return response

    def rdm_mute_device(self, manufacturer_uid: list, device_uid: list) -> bytes:
        """
        create and mute device packet
        -> Params:
                device_uid: device 6 bytes serial as list
                manufacturer_uid: device manufacturer uid  2 bytes
        <- Returns:
                mute command response as bytes
        """
        self._transaction_number += 1
        rdm_packet = (Commands.RDM_START,
                      Commands.SUB_START,
                      Commands.RDM_HEADER_18,
                      *manufacturer_uid,
                      *device_uid,
                      *self.device_serial,
                      self._transaction_number,
                      self.PORT,
                      *Commands.DISCOVERY,
                      *Commands.DISC_MUTE,
                      0)
        check_sum = PacketTools.calculate_checksum(rdm_packet)
        packet_header = self.create_header(0x0b, 26)
        packet = (*packet_header,
                  *rdm_packet,
                  *check_sum,
                  self.DMX_END_BYTES)
        response = self._execute(packet)
        return response

    def discovery(self) -> set:
        """
        Start device discovery process,first
        it will broadcast unmute command to unmute
        all muted device, then it will start discovery process.
        if descovery check sum is correct(usually good response
        will come with /xfe/xaa) it will decode uid and send the mute
        command and countinue the process. if the discovery response
        is ('~\x0c\x00\x00\xe7') its end of the process and can't
        find any device. depend on wiring and the branches the process
        must be repated over and over again to find uids
        @note:
              it will stop discovery after 1 min
              if its not finding any device
        """
        #
        start = time.time()
        discovered_device = set()
        self.rdm_disc_branch_umute()
        response = b"start"
        while response != Commands.RESPONSE_DMX_ACK:

            try:
                time.sleep(0.010)
                response = self.rdm_discovery()
                #Todo: refactor response translator
                if response.find(b'\xfe\xaa') > 1:
                    # manufacturer uid & device uid,
                    m_uid, device_uid, all_uids = UIDParser.decode(response)
                    self.rdm_mute_device(m_uid, device_uid)
                    print(all_uids)
                    discovered_device.add(all_uids)

            except InvalidCheckSum as err:
                print(err)
            except UidsNotFound as err:
                print(err)
            except ValueError as err:
                print(err)
                self._transaction_number = 0
            end = time.time()
            elapsed = end - start
            if elapsed > self._discovery_timeout:
                raise TimeOutError
        print(f'took -> {time.time() - start:.2f} second')
        self.rdm_disc_branch_umute()
        print(discovered_device)
        return discovered_device

    def close(self) -> None:
        """
        Close com port
        """
        self.com.close()

    def __enter__(self) -> object:
        return self

    def __exit__(self, ex_err: object, ex_ty: object, traceback: object) -> None:
        self.com.flushInput()
        self.com.flushOutput()
        self.com.close()


if __name__ == '__main__':
    discovered = set()
    parser = UIDParser()
    with RemoteDeviceManagment('COM4') as s:
        s.discovery()
