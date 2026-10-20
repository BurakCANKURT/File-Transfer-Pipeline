#include <iostream>
#include <vector>
#include <array>
#include <string>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
// Network
#include <winsock2.h>
#include <ws2tcpip.h>   

// Error Handling
#include <stdexcept>

class File
{
public:
    #pragma pack(push, 1)
    struct Header
    {   
        std::uint64_t file_size {0}; 
        std::uint32_t file_name_len {0};
        std::array<uint32_t, 32> sum{};  // TODO(v0.4.0): SHA-256 integrity check (unused)
    };
    #pragma pack(pop)

    #pragma pack(push, 1)
    struct MetaData
    {
        Header header;
        char file_name[256]; 
        std::vector<uint8_t> payload;
    };
    #pragma pack(pop)

    
    MetaData metadata;


    // File name security controller 
    static std::string safeFileName(const std::string& fileName){

        // Path Traversal Issue
        size_t lastSeperator = std::string::npos; // No position
        std::string safeFileName; 

       
        lastSeperator = fileName.find_last_of("/\\");

        // Path Traverse solution
        safeFileName =  (lastSeperator != std::string::npos) ? (fileName.substr(lastSeperator + 1)): fileName;

        // ADS Issue solution
        safeFileName = (safeFileName.find(':') != std::string::npos) ? throw std::runtime_error("[!] Unsupported file name format...\n"): safeFileName;

        // TODO(v0.4.0): switch to whitelist; reject control chars (ASCII 0-31) and trailing spaces
        safeFileName =  (safeFileName.find('*') != std::string::npos) ||
                        (safeFileName.find('<') != std::string::npos) ||
                        (safeFileName.find('|') != std::string::npos) ||
                        (safeFileName.find('"') != std::string::npos) ||
                        (safeFileName.find('>') != std::string::npos) ||
                        (safeFileName.find('?') != std::string::npos)  ? throw std::runtime_error("[!] Unsupported file name format...\n") : safeFileName;
        
        // Zero Byte Injection solution
        safeFileName = (safeFileName.find('\0') != std::string::npos) ? throw std::runtime_error("[!] Zero Byte Injection Detected!!!..."): safeFileName;
        
        // Path Manipulation solution
        safeFileName = (safeFileName.empty()) ? throw std::runtime_error("[!] Empty File Name Detected!!!..."): safeFileName;

        safeFileName = (safeFileName[0] == '.' || safeFileName.back() == '.') ? throw std::runtime_error("[!] Unsupported file name format...\n"): safeFileName; 

        return safeFileName;
    }


    // Reads a file in 64 KB chunks and prints progress
    void file_converter(){
        

        namespace fs = std::filesystem;

        // File size and path
        
        fs::path path = "video.mp4";
        

        if(!fs::exists(path)){
            std::cerr << "Path does not exists!";
            return;
        };

        uint64_t file_size = fs::file_size(path);
        uint64_t chunk_size = 64 * 1024;

        std::cout << "File: " << path.filename() << std::endl;

        std::cout << "File size: " << file_size << std::endl;

        

        // Open file in binary mode
        std::ifstream file(path, std::ios::binary);

        // Control the file 
        if(!file.is_open()){
            std::cerr  << "File is not found or not open!";
            return;
        };

        // Allocate a 64 KB buffer from the RAM.
        std::vector<char> chunk(chunk_size);
        uint64_t remaining = file_size;
        uint64_t total_read = 0; //
        
        // Retrieve the data in a LOOP
        while(remaining > 0 ){
            

            size_t to_read = (remaining < chunk_size) ? static_cast<std::size_t>(remaining): chunk_size;

            file.read(chunk.data(), to_read);

            // Get how many byte were read.
            std::streamsize bytes_read = file.gcount();

            remaining -=  bytes_read;

            // Check Error
            if(bytes_read <= 0){
                std::cerr << "Something is wrong!!!";
                break;
            } 


            // Live Received Data Percentage
            total_read += bytes_read;
            
            uint64_t percent = (total_read * 100)/ file_size;
            
            std::cout << "Status: %" << percent << " [" << total_read <<" / " << file_size << " byte]\n"  << std::flush;
        }

        

        // After reading the data confirm the data 
        std::streamsize received_byte_size = file.gcount();

        std::cout << "The file was read successfully. File size: " << received_byte_size << std::endl;
    };
    


    std::vector<uint8_t> serialize(const File::MetaData* metadata_ptr, const std::string& filename, const std::vector<uint8_t>& payload)
    {
        std::vector<uint8_t> packet;

        const uint8_t* byte_ptr = reinterpret_cast<const uint8_t*>(&metadata_ptr->header);

        // Header
        for(size_t i = 0; i < sizeof(File::Header); ++i){
            packet.push_back(byte_ptr[i]);
        }

        //static_cast --> To convert data type.
        // File name 
        for(size_t i = 0; i < filename.size(); ++i){
            packet.push_back(static_cast<uint8_t>(filename[i]));
        }

        // Payload
        for(size_t i = 0; i < payload.size();++i){
            packet.push_back(payload[i]);
        }

        return packet;
    };


    // Assume X byte buffer. [ --- Header --- +  --- file name --- + --- payload --- ] -> X byte
    const MetaData deserialization(const uint8_t* buffer)
    {   
        MetaData new_metadata; 
        
        //buffer          
        // |                 
        // v  
        // [ --- Header--- ]
        uint8_t* received_data_byte_ptr = reinterpret_cast<uint8_t*>(&new_metadata.header);

        for(size_t i = 0; i < sizeof(Header); ++i){
            received_data_byte_ptr[i] = buffer[i];
        }

        //buffer          Header address
        // |                  |
        // v                  v
        // [---  Header --- , --- File Name --- ]        
        strncpy(new_metadata.file_name, reinterpret_cast<const char*> (buffer + sizeof(Header)),metadata.header.file_name_len); // After that rest of the chars will be garbage. 
        new_metadata.file_name[new_metadata.header.file_name_len] = '\0';
        


        //buffer          Header address    File Names address
        // |                  |                  |
        // v                  v                  v   
        // [---  Header --- , --- File Name ---, --- Payload ---]   
        const uint8_t* start_add_ptr = reinterpret_cast<const uint8_t*>(buffer + sizeof(Header) + new_metadata.header.file_name_len); 

        for(const uint8_t* i = start_add_ptr; i < (start_add_ptr + new_metadata.header.file_size); ++i){
            new_metadata.payload.push_back(*i);
        }

    
        return new_metadata;
    }

    
};


#pragma comment(lib, "ws2_32.lib")
class Network
{
private: 
SOCKET sock;

public:
WSADATA wsaData;

Network() : sock(INVALID_SOCKET){
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    std::cerr << "WSAStartup error: " << WSAGetLastError() << "\n";
    }   

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket couldnt open: " << WSAGetLastError() << "\n";

    }
}

~Network() {
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
        sock = INVALID_SOCKET;
    }
    WSACleanup();
};   

bool connect_to(const std::string& ip, uint16_t port){
    sockaddr_in server_addr{};

    server_addr.sin_family = AF_INET; // IPv4 
    server_addr.sin_port = htons(port); // Big-Endien format port.
    inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr); // Converts the string IP address into binary format and writes it into memory

    int res = ::connect(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr));

    if (res == SOCKET_ERROR) {
        int error = WSAGetLastError();
        std::cerr << "[!] Connection could not be established... " << error << std::endl;
        return false;
        // 10061: WSACONNREFUSED
        // 10060: WSATIMEDOUT
    } 
    
    std::cout << "[+] 3-Way Handshake has completed, pipeline is active.\n"; 
    

    return true;
}



bool recv_all(SOCKET s, char* buffer, size_t total_bytes){
    size_t total_recv = 0;

    while (total_recv < total_bytes){
        // Remaining: total_bytes - total_recv
        // Memory Address: buffer + total_recv 
        int bytes = ::recv(s, buffer + total_recv, static_cast<int>(total_bytes - total_recv), 0);
        if (bytes == SOCKET_ERROR){
            std::cerr << "[!] recv error: " << WSAGetLastError() << std::endl;
            return false; 
        }
        if (bytes==0){
            // In TCP recv() 0 means: Target terminated the connection 
            std::cerr << "[!] Connection lost... ";
            return false; 
        }
        total_recv +=bytes;
    }
    return true;
}

bool receiver(uint16_t port){
    // Create listener sock and check its status
    if (sock == INVALID_SOCKET) {
        sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET; // IPv4
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;


    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    // == Bind ==
    if (::bind(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "[!] Bind error! Error code: " << WSAGetLastError() << "\n";
        closesocket(sock);
        return false;
    }

    // == Listen --> sock == 
    if (::listen(sock, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "[!] Listen failed! Error code: " << WSAGetLastError() << "\n";
        closesocket(sock);
        return false;
    }

    std::cout << "[*] Port " << port << " listening, Connecting...\n";

    // == Accept ==
    sockaddr_in client_addr{};
    int client_len = sizeof(client_addr);

    SOCKET client_sock = ::accept(sock, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
    if (client_sock == INVALID_SOCKET) {
        std::cerr << "[!] Accept failed! Error code: " << WSAGetLastError() << "\n";
        closesocket(sock);
        return false;
    }

    // == Data Reading --> client_sock ==
    File::Header header{}; 
    if(!recv_all(client_sock, reinterpret_cast<char*>(&header), sizeof(header))){
        std::cerr << "[!] Header couldnt be retrieved...\n";
        closesocket(client_sock);
        closesocket(sock);
        return false;
    }
    // Validate file_name_len (1-255) and file_size before allocation

    constexpr uint32_t MAX_NAME_LEN = 255;

    if (header.file_name_len == 0 || header.file_name_len > MAX_NAME_LEN) {
        std::cerr << "[!] Invalid file name length: " << header.file_name_len << "\n";
        closesocket(client_sock);
        closesocket(sock);
        return false;
    }
    

    constexpr uint64_t MAX_FILE_SIZE = 10ULL * 1024 * 1024* 1024; 

    if(header.file_size > MAX_FILE_SIZE){
        std::cerr << "[!] File size exceeds limit: " << header.file_name_len << "\n";
        closesocket(client_sock);
        closesocket(sock);
        return false;
    }

    std::string filename(header.file_name_len, '\0');
        // Read the file name
        
        if(!recv_all(client_sock, &filename[0], header.file_name_len)){
            std::cerr << "[!] File name couldnt be retrieved...\n";
            closesocket(client_sock);
            closesocket(sock);
            return false;
        }
    
    
    std::cout << "[+] Incoming file: " << filename << " (" << header.file_size << " byte)\n";



    // catch exceptions from safeFileName (uncaught throw -> DoS)
    std::string safeFName;
    try{
        safeFName = File::safeFileName(filename);
    } catch (const std::exception& e){
        std::cerr << e.what() << "\nRejecting connection...\n";
        closesocket(client_sock);
        closesocket(sock); 
        return false;
    }
    

   
    
    std::ofstream out_file("received_" + safeFName, std::ios::binary);
    if(!out_file.is_open()){
        std::cerr << "[!] The file couldnt be written to the disk...\n";
        closesocket(client_sock);
        closesocket(sock);
        return false;
    }
    // Get 64 KB file chunk by chunk and write to the disk
    constexpr size_t CHUNK_SIZE = 64 * 1024;
    std::vector<char> chunk_buffer(CHUNK_SIZE);
    uint64_t bytes_remaining = header.file_size;
    
    while (bytes_remaining > 0){
        size_t to_read = (bytes_remaining < CHUNK_SIZE) ? static_cast<size_t>(bytes_remaining) : CHUNK_SIZE;

        if (!recv_all(client_sock, chunk_buffer.data(), to_read)){
            std::cerr << "[!] Data was lost during transmission!\n";
            out_file.close();
            closesocket(client_sock);
            closesocket(sock);
            return false;
        }

        out_file.write(chunk_buffer.data(), to_read);
        bytes_remaining -= to_read;
    }

    std::cout << "[+] The file succesfull completed and saved!\n";

    out_file.close();
    closesocket(client_sock);
    closesocket(sock);
    sock = INVALID_SOCKET;
    return true;
}


bool send_all(SOCKET s, const char* buffer, size_t total_bytes){
    size_t total_sent = 0;

    while (total_sent < total_bytes){
        // buffer + total_sent
        // total_bytes - total_sent
        int bytes = ::send(s, buffer + total_sent, static_cast<int>(total_bytes - total_sent), 0);  

        if (bytes == SOCKET_ERROR) {
            std::cerr << "[!] send error: " << WSAGetLastError() << std::endl;
            return false;
        }

        total_sent +=bytes; 
    }
    return true; // All bytes are transferred to OS's buffer
}


bool send_file(const std::string& filepath){
    // Check file existance
    std::filesystem::path p(filepath);
    if (!std::filesystem::exists(p)){
        std::cerr << "[!] File to be sent not found: " << filepath << "\n";
        return false;
    } 

    uint64_t file_size = std::filesystem::file_size(p);
    std::string filename = p.filename().string();
    uint32_t filename_len = static_cast<uint32_t>(filename.length());

    // Fill FileHeader and send
    File::Header header{};
    header.file_size = file_size;
    header.file_name_len = filename_len;

    if(!send_all(sock,reinterpret_cast<const char*>(&header), sizeof(header))){
        std::cerr << "[!] Header couldnt be send...\n";
        return false;
    }

    // Send file name
    if (!send_all(sock,filename.c_str(), filename_len)){
        std::cerr << "[!] File name could not be send...\n";
        return false;
    }

    // Open the file in binary mode
    std::ifstream in_file(filepath, std::ios::binary);
    if(!in_file.is_open()){
        std::cerr << "[!] The file could not be read...\n";
        return false;
    }

    // Read from disk and send as 64 KB chunks   
    constexpr size_t CHUNK_SIZE = 64 * 1024;
    std::vector<char> buffer(CHUNK_SIZE);
    uint64_t bytes_remaining = file_size;

    while (bytes_remaining > 0){
        size_t to_send = (bytes_remaining < CHUNK_SIZE) ? static_cast<size_t>(bytes_remaining) : CHUNK_SIZE;    

        // Read from disk to RAM 
        in_file.read(buffer.data(), to_send);

        // Send from RAM to network

        if(!send_all(sock, buffer.data(), to_send)){
            std::cerr << "[!] Connection lost during data transmittion... \n";
            return false;
        }

        bytes_remaining -= to_send;
    }

    std::cout << "[+] The file was sent succesfull: " << filename<<"( " << file_size << "byte )\n";
    return true;
}
};

int main(int argc, char* argv[])
{

    // 1. Initializing Winsock 
    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2,2), &wsa) != 0){
        std::cerr << "[!] WSAStartup error: " << WSAGetLastError() <<"\n";
        return 1;
    }

    if (argc < 2){
        std::cout << "Usage: \n" 
        << "Server mode: " <<argv[0] << " server <port>\n"
        << "Client mode: " << argv[0] << " client <ip><port><file_path>\n";
        WSACleanup();
        return 1;
    }

    std::string mode = argv[1];

    if(mode == "server"){
        if(argc < 3){
            std::cerr << "[!] Must define port number.\n";
            WSACleanup();
            return 1;
        }

        uint16_t port =static_cast<uint16_t>(std::stoi(argv[2]));

        // Start listening

        Network server;
        server.receiver(port);

        std::cout << "[*] Working on server mode.\n";
    }else if(mode == "client"){
        if(argc < 5){
            std::cerr << "[!] IP,Port and Path not defined.\n";
            WSACleanup();
            return 1;
        }

        std::string ip = argv[2];
        uint16_t port = static_cast<uint16_t>(std::stoi(argv[3]));
        std::string filepath = argv[4];

        // Connect and Send 

        Network client;
        if(client.connect_to(ip, port)){
            client.send_file(filepath);
        }
    
        std::cout << "[*] Working on Client Mode.\n";
    } else {
        std::cerr << "[!] Invalid mode: " << mode << "\n";
    }

    // 2. Clean Winsock 
    WSACleanup();
    return 0;
}   


