//PCAP head: 24byte
//  4 - magic. a1b2c3d4 или d4c3b2a1
//  2 - major. Номер версии текущего файла
//  2 - minor. Дополнительная версия текущего файла
//  4 - ThisZone. Временная зона
//  4 - SigFig. Точность времени
//  4 - SnapLen. Максимальная длина захваченных пакетов. 65535 - все данные захачены
//  4 - LinkType. Тип ссылки. 802.11 - 105
//
//DATA head: 16byte
//  4 - TimeStamp. Unix время с точностью до сек
//  4 - TimeStamp. Миллисекунды
//  4 - CapLen. Длина захваченного кадра данных
//  4 - Len. Длина факического кадра в сети
//
//Ethernet
//  2 - frame control (ver, type, subtype ...)
//  2 - duration/id
//  ...
//  6 - type. Тип следующего протокола. IPv4 - 0800
//  64-1500 - data
//  4 - fcs. CRC32 0xEDB88320
// 
//Sources:
// Calc CRC-32: https://www.scadacore.com/tools/programming-calculators/online-checksum-calculator/
// Frame structure: https://www.rhyshaden.com/wifi_frm.htm
// Frame structure: https://tech-geek.ru/creating-sniffer-esp32/
// Frame structure: https://flylib.com/books/en/2.519.1/management_frames.html
// Frame structure: https://howiwifi.com/2020/07/13/802-11-frame-types-and-formats/
// Frame structure: https://howiwifi.com/2020/07/16/802-11-frame-exchanges/
// Frame structure: https://en.wikipedia.org/wiki/802.11_Frame_Types#+HTC/Order
// Frame structure: https://dalewifisec.wordpress.com/2014/05/17/the-to-ds-and-from-ds-fields/
// Frame structure: http://bos-info.com/wireless/wireless_frames.html
// Frame structure: https://zvondozvon.ru/tehnologii/kompyuternye-seti/format-kadra-wi-fi#_Wi8212Fi_MAC
// Find vendor: https://macaddress.io/
// Find vendor: https://macvendors.com/
//

#include "Topology.h"
#include <iostream>
#include <fstream>
#include <string>
#include <limits>
#include <bitset>
#include <sstream>
#include <vector>

using namespace std;
using uchar = unsigned char;

void pcap_parser(string);
void parse_data(vector<uchar>);

string get_mac(vector<uchar>, int);
string get_ssid(vector<uchar>, int, int);
string get_hex(vector<uchar>, int, int);
string get_type(string, string);

string int_to_bin(uchar);
string int_to_hex(unsigned int);

bool check_fcs(vector<uchar>);
unsigned int get_CRC32(vector<uchar>, unsigned long); // calc FCS

Topology topology;

int main() {
    string user_input = "";

    cout << "11 - 3dr_solo. dsss" << endl;
    cout << "11 - 3dr_solo. wifi-ofdm-20" << endl;
    cout << "21 - fimi_x8_me_2020. 1wifi_fc_5825000000_fs_12000000.pcm.result" << endl;
    cout << "22 - fimi_x8_me_2020. 2wifi_fc_5825000000_fs_12000000.pcm.result" << endl;
    cout << "23 - fimi_x8_me_2020. wifi_fc_5825000000_fs_12000000.pcm.result" << endl;
    cout << "31 - hubsan_zino_2. Vega_2021-03-30_15-13-49-781_1_5785000000_10000000_11764706" << endl;
    cout << "41 - nelk_b6. NELK_B6_Downlink 5220.213483MHz 46625.000000KHz.pcm" << endl;
    cout << "51 - parrot_bebop2. on_the_ground_gps - dsss" << endl;
    cout << "52 - parrot_bebop2. on_the_ground_gps - ofdm-20" << endl;
    cout << "61 - skydio2. 3 ������祭�� App, �����஢��, ����⪠ ����� - Unsafe space" << endl;
    cout << "62 - skydio2. 4 ����� � ��ᠤ�� � ���" << endl;
    cout << "0 - exit" << endl;
    cout << "Or type path to *.pcap file" << endl;
    cout << endl;

    std::cout << "\n\n" << "Type path to *.pcap file or select menu item: ";
    std::cin >> user_input;

    while (user_input != "0") {
        if (user_input == "11")
            user_input = "Source/frames1_1.pcap";
        else if (user_input == "12")
            user_input = "Source/frames1_2.pcap";
        else if (user_input == "21")
            user_input = "Source/frames2_1.pcap";
        else if (user_input == "22")
            user_input = "Source/frames2_2.pcap";
        else if (user_input == "23")
            user_input = "Source/frames2_3.pcap";
        else if (user_input == "31")
            user_input = "Source/frames3_1.pcap";
        else if (user_input == "41")
            user_input = "Source/frames4_1.pcap";
        else if (user_input == "51")
            user_input = "Source/frames5_1.pcap";
        else if (user_input == "52")
            user_input = "Source/frames5_2.pcap";
        else if (user_input == "61")
            user_input = "Source/frames6_1.pcap";
        else if (user_input == "62")
            user_input = "Source/frames6_2.pcap";

        clock_t time_spent = clock();
        pcap_parser(user_input);
        std::cout << "Time elapsed: " << clock() - time_spent + 1 << "ms.\n";

        topology = Topology();
        std::cout << "\n\nType path to *.pcap file or select menu item: ";
        std::cin >> user_input;
    }

    return 0;
}


void pcap_parser(string file_name) {
    int mode = 0; //0 - read PCAP head: 24byte
                  //1 - read DATA head: 16byte
                  //2 - read data
    unsigned int data_len;
    vector<uchar> datagram;
    uchar byte;
    unsigned short num_frames = 0, fcs_ok = 0;


    //open file
    ifstream pcapFile(file_name, ios::binary);
    pcapFile >> noskipws;   //no skip: " ", "\t", "\n"
    if (!pcapFile.is_open()) {
        std::cout << "Error: couldn't open file. Try again.\n";
        return;
    }

    while (pcapFile >> byte) {
        datagram.push_back(byte);

        if (mode == 0 && datagram.size() == 24) { //pcap header
            int link_type = datagram[23] * 16777216 + datagram[22] * 65536 + datagram[21] * 256 + datagram[20];
            std::cout << "Link type: " << link_type << "\n\n";

            //change mode: read head data
            mode = 1;
            datagram.clear();
        }
        else if (mode == 1 && datagram.size() == 16) { //data header
            num_frames++;

            data_len = datagram[15] * 16777216 + datagram[14] * 65536 + datagram[13] * 256 + datagram[12];
            std::cout << "Frame: " << num_frames << endl;
            std::cout << "Data length: " << data_len << endl;

            //change mode: read data
            mode = 2;
            datagram.clear();
        }
        else if (mode == 2 && datagram.size() == data_len) { //data(frame 802.11)
            if (check_fcs(datagram)) {
                fcs_ok++;
                std::cout << "FCS: OK\n";

                parse_data(datagram);
            }
            else
                std::cout << "FCS: FAIL\n\n";

            //change mode: read data head
            mode = 1;
            datagram.clear();
        }
    }
    pcapFile.close();
    datagram.clear();

    //Statistics
    float fcs_ok_prop = 0;
    if (fcs_ok != 0)
        fcs_ok_prop = (float)fcs_ok / num_frames * 100;

    std::cout << "\n\nNumber of frames: " << num_frames << "\n";
    std::cout << "FCS OK: " << fcs_ok << "(" << fcs_ok_prop << "%)\n";
    std::cout << "FCS FAIL: " << num_frames - fcs_ok << "(" << 100 - fcs_ok_prop << "%)\n";

    cout << "\n";
    topology.show_net_stat();
    cout << "\n";
    topology.show_unknown_frames();
    cout << "\n\n";
}


bool check_fcs(vector<uchar> data) {
    unsigned int fcs = data[data.size() - 1] * 16777216 + data[data.size() - 2] * 65536 + data[data.size() - 3] * 256 + data[data.size() - 4];

    if (fcs == get_CRC32(data, data.size() - 4))
        return true;

    return false;
}

unsigned int get_CRC32(vector<uchar> data, unsigned long len) { //crc32 0xEDB88320
    unsigned long crc_table[256];
    unsigned long crc;

    for (int i = 0; i < 256; i++) {
        crc = i;
        for (int j = 0; j < 8; j++)
            crc = crc & 1 ? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;
        crc_table[i] = crc;
    };
    crc = 0xFFFFFFFFUL;

    for (unsigned long i = 0; i < len; i++)
        crc = crc_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);

    return crc ^ 0xFFFFFFFFUL;
}

string int_to_hex(unsigned int value) {
    string result = "";
    std::stringstream stream;
    stream << std::hex << value;

    if (stream.str().length() == 1)
        result = "0" + stream.str();
    else
        result = stream.str();

    return result;
}

string int_to_bin(uchar value) {
    return bitset<8>(value).to_string();
}


void parse_data(vector<uchar> data) {
    //frame control
    string frame_control = int_to_bin(data[0]) + int_to_bin(data[1]);
    std::cout << "\t Frame control: " << frame_control << endl;

    //get type/subtype
    string type_bin = frame_control.substr(4, 2);
    string subtype_bin = frame_control.substr(0, 4);
    string type = get_type(type_bin, subtype_bin);
    std::cout << "\t\t Type/subtype: " << type << endl;

    //get to/from ds
    string to_ds = frame_control.substr(15, 1);
    string from_ds = frame_control.substr(14, 1);
    std::cout << "\t\t To DS: " << to_ds << endl;
    std::cout << "\t\t From DS: " << from_ds << endl;

    //get Duration/ID
    string duration_id = int_to_hex(data[2]) + int_to_hex(data[3]);
    std::cout << "\t Duration/ID: " << duration_id << endl;

    //get MAC
    //type == Management
    if (type_bin == "00") {
        string mac_dst = get_mac(data, 4);
        string mac_src = get_mac(data, 10);
        string bssid = get_mac(data, 16);

        std::cout << "\t mac_dst: " << mac_dst << endl;
        std::cout << "\t mac_src: " << mac_src << endl;
        std::cout << "\t bssid: " << bssid << endl;

        topology.add_pair(mac_src, mac_dst, "00");

        if (subtype_bin == "1000" || subtype_bin == "0101") { //Beacon, Probe response
            int size = data[37];
            string ssid = get_ssid(data, 38, size);
            topology.set_ssid(mac_src, ssid);
        }
    }
    //type == Control
    else if (type_bin == "01") {
        //RTS
        if (subtype_bin == "1011") {
            string mac_receiver = get_mac(data, 4);
            string mac_transmitter = get_mac(data, 10);

            std::cout << "\t mac_receiver: " << mac_receiver << endl;
            std::cout << "\t mac_transmitter: " << mac_transmitter << endl;

            //topology.add_network(mac_receiver);s
            topology.add_pair(mac_receiver, mac_transmitter, "01");
        }
        //Block ACK request, Block ACK, Beamforming Report Poll, VHT/HE NDP Announcement
        else if (subtype_bin == "1000" || subtype_bin == "1001" || subtype_bin == "0100" || subtype_bin == "0101") {
            string mac_receiver = get_mac(data, 4);
            string mac_transmitter = get_mac(data, 10);

            std::cout << "\t mac_receiver: " << mac_receiver << endl;
            std::cout << "\t mac_transmitter: " << mac_transmitter << endl;

            topology.add_pair(mac_receiver, mac_transmitter, "01");
        }
        //CTS
        else if(subtype_bin == "1100") {
            string mac_receiver = get_mac(data, 4);
            std::cout << "\t mac_receiver: " << mac_receiver << endl;

            //topology.add_network(mac_receiver);
            topology.add_pair(mac_receiver, "", "01");
        }
        //ACK, Control wrapper
        else if (subtype_bin == "1101" || subtype_bin == "0111") {
            string mac_receiver = get_mac(data, 4);
            std::cout << "\t mac_receiver: " << mac_receiver << endl;

            topology.add_pair(mac_receiver, "", "01");
        }
        //PS-POLL
        else if (subtype_bin == "1010") {
            string mac_receiver = get_mac(data, 4);
            string mac_transmitter = get_mac(data, 10);

            std::cout << "\t mac_receiver(BSSID): " << mac_receiver << endl;
            std::cout << "\t mac_transmitter: " << mac_transmitter << endl;

            topology.add_network(mac_receiver);
            topology.add_pair(mac_receiver, mac_transmitter, "01");
        }
        //CF-End/CF-END+CF-ACK
        else if (subtype_bin == "1110" || subtype_bin == "1111") {
            string mac_receiver = get_mac(data, 4);
            string mac_transmitter = get_mac(data, 10);

            std::cout << "\t mac_receiver: " << mac_receiver << endl;
            std::cout << "\t mac_transmitter(BSSID): " << mac_transmitter << endl;

            topology.add_network(mac_transmitter);
            topology.add_pair(mac_receiver, mac_transmitter, "01");
        }
        //Control Frame Extension
        else if (subtype_bin == "0110") {}
    }
    //type == Data
    else if (type_bin == "10") {
        if (to_ds == "0" && from_ds == "0") {
            string mac_dst = get_mac(data, 4);
            string mac_src = get_mac(data, 10);
            string bssid = get_mac(data, 16);

            std::cout << "\t mac_dst: " << mac_dst << endl;
            std::cout << "\t mac_src: " << mac_src << endl;
            std::cout << "\t bssid: " << bssid << endl;

            //topology.add_network(bssid);
            topology.add_pair(mac_src, mac_dst, "10");
        }
        else if (to_ds == "1" && from_ds == "0") {
            string bssid = get_mac(data, 4);
            string mac_src = get_mac(data, 10);
            string mac_dst = get_mac(data, 16);

            std::cout << "\t mac_dst: " << mac_dst << endl;
            std::cout << "\t mac_src: " << mac_src << endl;
            std::cout << "\t bssid: " << bssid << endl;

            //topology.add_network(bssid);
            topology.add_pair(mac_src, mac_dst, "10");
        }
        else if (to_ds == "0" && from_ds == "1") {
            string mac_dst = get_mac(data, 4);
            string bssid = get_mac(data, 10);
            string mac_src = get_mac(data, 16);

            std::cout << "\t mac_dst: " << mac_dst << endl;
            std::cout << "\t mac_src: " << mac_src << endl;
            std::cout << "\t bssid: " << bssid << endl;

            //topology.add_network(bssid);
            topology.add_pair(mac_src, mac_dst, "10");
        }
        else if (to_ds == "1" && from_ds == "1") {
            string mac_receiver = get_mac(data, 4);
            string mac_transmitter = get_mac(data, 10);
            string mac_dst = get_mac(data, 16);
            string mac_src = get_mac(data, 24);

            std::cout << "\t mac_receiver: " << mac_receiver << endl;
            std::cout << "\t mac_transmitter: " << mac_transmitter << endl;
            std::cout << "\t mac_dst: " << mac_dst << endl;
            std::cout << "\t mac_src: " << mac_src << endl;

            topology.add_pair(mac_src, mac_dst, "10");

            if (mac_src != mac_transmitter) {
                //topology.add_network(mac_transmitter);
                //topology.add_pair(mac_src, mac_transmitter, "10");
            }
            if (mac_transmitter != mac_receiver) {
                //topology.add_pair(mac_transmitter, mac_receiver, "10");
            }
            if (mac_receiver != mac_dst) {
                //topology.add_network(mac_receiver);
                //topology.add_pair(mac_receiver, mac_dst, "10");
            }
        }
    }
    // type == Extension
    else if (type_bin == "11") {}

    std::cout << endl;
}


string get_mac(vector<uchar> data, int pos) {
    return get_hex(data, pos, 6);
}


string get_hex(vector<uchar> data, int pos, int num) {
    string result = "";

    for (int i = 0; i < num; i++)
        result += int_to_hex(data[pos + i]);

    return result;
}


string get_ssid(vector<uchar> data, int pos, int num) {
    string result = "";

    for (int i = 0; i < num; i++)
        result += tolower(data[pos + i]);

    return result;
}


string get_type(string type_bin, string sub_type_bin) {
    string type = "", subtype = "";

    if (type_bin == "00") {
        type = "Management";
        if (sub_type_bin == "0000")
            subtype = "Association Request";
        else if (sub_type_bin == "0001")
            subtype = "Association Response";
        else if (sub_type_bin == "0010")
            subtype = "Reassociation Request";
        else if (sub_type_bin == "0011")
            subtype = "Reassociation Response";
        else if (sub_type_bin == "0100")
            subtype = "Probe Request";
        else if (sub_type_bin == "0101")
            subtype = "Probe Response";
        else if (sub_type_bin == "0110")
            subtype = "Timing Advertisement";
        else if (sub_type_bin == "0111")
            subtype = "Reserved";
        else if (sub_type_bin == "1000")
            subtype = "Beacon";
        else if (sub_type_bin == "1001")
            subtype = "ATIM";
        else if (sub_type_bin == "1010")
            subtype = "Disassociation";
        else if (sub_type_bin == "1011")
            subtype = "Authentication";
        else if (sub_type_bin == "1100")
            subtype = "Deauthentication";
        else if (sub_type_bin == "1101")
            subtype = "Action";
        else if (sub_type_bin == "1110")
            subtype = "Action No Ack";
        else if (sub_type_bin == "1111")
            subtype = "Reserved";
    }
    else if (type_bin == "01") {
        type = "Control";
        if (sub_type_bin <= "0000" && sub_type_bin >= "0010")
            subtype = "Reserved";
        else if (sub_type_bin == "0011")
            subtype = "TACK";
        else if (sub_type_bin == "0100")
            subtype = "Beamforming Report Poll";
        else if (sub_type_bin == "0101")
            subtype = "VHT/HE NDP Announcement";
        else if (sub_type_bin == "0110")
            subtype = "Control Frame Extension";
        else if (sub_type_bin == "0111")
            subtype = "Control Wrapper";
        else if (sub_type_bin == "1000")
            subtype = "Block Ack Request";
        else if (sub_type_bin == "1001")
            subtype = "Block Ack";
        else if (sub_type_bin == "1010")
            subtype = "PS-Poll";
        else if (sub_type_bin == "1011")
            subtype = "RTS";
        else if (sub_type_bin == "1100")
            subtype = "CTS";
        else if (sub_type_bin == "1101")
            subtype = "ACK";
        else if (sub_type_bin == "1110")
            subtype = "CF-End";
        else if (sub_type_bin == "1111")
            subtype = "CF-End + CF-ACK";
    }
    else if (type_bin == "10") {
        type = "Data";
        if (sub_type_bin == "0000")
            subtype = "Data";
        else if (sub_type_bin == "0001")
            subtype = "Reserved";
        else if (sub_type_bin == "0010")
            subtype = "Reserved";
        else if (sub_type_bin == "0011")
            subtype = "Reserved";
        else if (sub_type_bin == "0100")
            subtype = "Null";
        else if (sub_type_bin == "0101")
            subtype = "Reserved";
        else if (sub_type_bin == "0110")
            subtype = "Reserved";
        else if (sub_type_bin == "0111")
            subtype = "Reserved";
        else if (sub_type_bin == "1000")
            subtype = "QoS Data";
        else if (sub_type_bin == "1001")
            subtype = "QoS Data + CF-ACK";
        else if (sub_type_bin == "1010")
            subtype = "QoS Data + CF-Poll";
        else if (sub_type_bin == "1011")
            subtype = "QoS Data + CF-ACK + CF-Poll";
        else if (sub_type_bin == "1100")
            subtype = "QoS Null";
        else if (sub_type_bin == "1101")
            subtype = "Reserved";
        else if (sub_type_bin == "1110")
            subtype = "QoS CF-Poll";
        else if (sub_type_bin == "1111")
            subtype = "QoS CF-ACK + CF-Poll";
    }
    else if (type_bin == "11") {
        type = "Extension";
        if (sub_type_bin == "0000")
            subtype = "DMG Beacon";
        else if (sub_type_bin == "0001")
            subtype = "S1G Beacon";
        else
            subtype = "Reserved";
    }

    return type + "/" + subtype;
}

//Что нужно сделать:
//
//Выполнено:
// - Исправить отображение графа
// - Исправить коллизию в количестве фреймов между разными сетями
// - Проверить корректность обнаружения новой ap
//   Вывод: находятся новые ap, если принимать поле bssid во фреймах data
// - Проверить разбор фреймов на правильность входа/выхода
// - Перепроверить методику подсчета fcs_ok
//      Есть противоречие с .log файлами. Однако статистика совпадает с парсером wireshark
// - Сверить количество фреймов с fcs_ok
// - Реализовать определение вендора по mac
// - Вычистить код
// - Пересобрать файлы по аналогии с имитатором от СТЦ
// - Подготовить отчет
//