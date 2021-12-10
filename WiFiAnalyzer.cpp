#include <iostream>
#include <fstream>
#include <string>
#include <limits>
#include <bitset>
#include <sstream>

//PCAP head: 24b
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
//  6byte - MAC Destination
//  6byte - MAC Source
//  6byte - type. Тип следующего протокола. IPv4 - 0800
//  64-1500 byte - data
//  4byte - fcs. CRC32 0xEDB88320
// 


using namespace std;
using uchar = unsigned char;

void pcap_parser(string);
unsigned int getCRC32(unsigned char*, unsigned long); // calc FCS
string int_to_bin(uchar);
string int_to_hex(unsigned int);
string get_type(uchar);


int main()
{
    string menu = "";
    string file_name = "";
    while (menu != "0")
    {
        cout << "\n\nPath to *.pcap file: ";
        cin >> file_name;                       //Source/frames1_1.pcap

        clock_t time_spent = clock();
        pcap_parser(file_name);
        cout << "Time elapsed: " << clock() - time_spent + 1 << "ms.\n";


        cout << "\nType any symbol to load new file, 0 - to exit: ";
        cin >> menu;
    }


    return 0;
}


void pcap_parser(string file_name)
{
    int status = 0; //0 - read PCAP and DATA head: 24byte
                    //1 - read DATA head: 16byte
                    //3 - read data
    unsigned short data_len = 24;
    uchar* data = new uchar[data_len];
    uchar byte;
    unsigned short num = 0;

    unsigned short num_frames = 0, fcs_ok = 0;


    //open file
    ifstream pcapFile(file_name, ios::binary);
    pcapFile >> noskipws;   //no skip: " ", "\t", "\n"
    if (!pcapFile.is_open())
    {
        cout << "Error: couldn't open file. Try again.\n";
        return;
    }

    while (pcapFile >> byte)
    {
        data[num] = byte;
        num++;

        if (status == 0 && num == 24) { //pcap header

            int link_type = data[23] * 16777216 + data[22] * 65536 + data[21] * 256 + data[20];
            cout << "Link type: " << link_type << "\n\n";

            //change mode to read head data
            num = 0;
            status = 1;
            delete[] data;
            data = new uchar[16];
        }
        else if (status == 1 && num == 16) { //data header
            num_frames++;

            data_len = data[15] * 16777216 + data[14] * 65536 + data[13] * 256 + data[12];

            cout << "Frame: " << num_frames << endl;
            cout << "Data length: " << data_len << endl;


            //change mode to read data
            num = 0;
            status = 2;
            delete[] data;
            data = new uchar[data_len];
        }
        else if (status == 2 && num == data_len) { //data
            //check FCS
            unsigned int fcs = data[data_len - 1] * 16777216 + data[data_len - 2] * 65536 + data[data_len - 3] * 256 + data[data_len - 4];

            if (fcs == getCRC32(data, data_len - 4))
            {
                fcs_ok++;
                cout << "FCS: OK\n";

                //get type/subtype
                string type = get_type(data[0]);
                cout << "\tType/subtype: " << type << endl;

                //get tDuration/ID
                string duration_id = int_to_hex(data[2] * 256 + data[3]);
                cout << "\tDuration/ID: " << duration_id << endl;

                //get MAC
                if (int_to_bin(data[0]).substr(4, 2) == "00") { //if type == Management
                    string mac_dst = int_to_hex(data[4]) + int_to_hex(data[5]) + int_to_hex(data[6]) +
                        int_to_hex(data[7]) + int_to_hex(data[8]) + int_to_hex(data[9]);
                    cout << "\tMAC dst: " << mac_dst << endl;

                    string mac_src = int_to_hex(data[10]) + int_to_hex(data[11]) + int_to_hex(data[12]) +
                        int_to_hex(data[13]) + int_to_hex(data[14]) + int_to_hex(data[15]);
                    cout << "\tMAC src: " << mac_src << endl;
                }

                cout << endl;
            }
            else
            {
                cout << "FCS: FAIL\n\n";
            }

            //change mode to read data head
            num = 0;
            status = 1;
            delete[] data;
            data = new uchar[16];
        }
    }
    pcapFile.close();
    delete[] data;


    //Stat
    float fcs_ok_prop = 0;
    if (fcs_ok != 0)
    {
        fcs_ok_prop = (double)fcs_ok / num_frames * 100;
    }
    cout << "\n\nNumber of frames: " << num_frames << "\n";
    cout << "FCS OK: " << fcs_ok << "(" << fcs_ok_prop << "%)\n";
    cout << "FCS FAIL: " << num_frames - fcs_ok << "(" << 100 - fcs_ok_prop << "%)\n";
}


unsigned int getCRC32(unsigned char* buf, unsigned long len) //crc32 0xEDB88320
{
    unsigned long crc_table[256];
    unsigned long crc;

    for (int i = 0; i < 256; i++)
    {
        crc = i;
        for (int j = 0; j < 8; j++)
        {
            crc = crc & 1 ? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;
        }
        crc_table[i] = crc;
    };
    crc = 0xFFFFFFFFUL;

    while (len--)
    {
        crc = crc_table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFFUL;
}


string int_to_hex(unsigned int value)
{
    string result = "";
    std::stringstream stream;
    stream << std::hex << value;

    if (stream.str().length() == 1)
        result = "0" + stream.str();
    else
        result = stream.str();


    return result;
}

string int_to_bin(uchar value)
{
    return bitset<8>(value).to_string();
}

string get_type(uchar value)
{
    string value_bin = int_to_bin(value);
    string type_bin = value_bin.substr(4, 2);
    string sub_type_bin = value_bin.substr(0, 4);
    string type = "", subtype = "";

    if (type_bin == "00")
    {
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
    else if (type_bin == "01")
    {
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
    else if (type_bin == "10")
    {
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
    else if (type_bin == "11")
    {
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

