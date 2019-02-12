#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <string>
#include <sstream>
#include <iostream>
#include <document.h>
#include <assert.h>
#include <stream.h>
#include <sqlite3.h>
#include <pthread.h>
#include <unistd.h>
#include <list>
#include <set>
#include <mutex>
#include <fstream>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <execinfo.h>

#define NODEINFO_DATABASE "./nodes_info.db"
#define PORTINFO_DATABASE "./rpc_ports_info.db"
#define TESTED_RECORDS    "./tested_ips.rec"
#define FGET_BUF_SIZE 512
#define FOUND_PORT_MARK "Discovered open port "
#define TIMEOUT 60L
#define SOCKET_WAIT_TIME TIMEOUT
#define CONN_TIMEOUT_SEC 5
#define POOL_LIMIT 8
#define BACKTRACE_SIZE 32

size_t pool_limit = POOL_LIMIT;

// TODO delete DEBUG
// #define MASSCAN_CMD_MOD "masscan %s -p8545,22,443 2>/dev/null"

//TODO change to below!
#define MASSCAN_CMD_MOD "masscan %s --ports 0-65535 2>/dev/null"

char DEFAULT_PLATFORM[] = "kame_at_hk";
struct curl_slist *hs;
std::set<std::string> ip_set;
std::set<std::string> test_records;
std::list<char*> test_pool;
sqlite3 *result_db;
std::mutex r_mtx;
bool single_thread = false;

std::ofstream rec_fout;

enum AQRESULT{
    Success,
    Failed,
    Empty
};

static void * analyze_ip(void* ip);
bool checkAddrExist(char const * ip, int port);
bool net_version(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream);
bool web3_clientVersion(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream);
bool rpc_modules(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream);
bool eth_hashrate(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream);
bool eth_mining(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream);
bool eth_protocolVersion(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream);
bool parity_chainId(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream);
AQRESULT eth_accounts(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream);
AQRESULT parity_allAccountsInfo(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream);
AQRESULT personal_listAccounts(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream);

size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream) {
    size_t length = size * nmemb;
    std::string data((const char*) ptr, length);
    *((std::stringstream*) stream) << data;
    return length;
}

static int nodeinfo_callback(void *data, int argc, char **argv, char **azColName){
    for(int i = 0; i < argc; i++){
        std::string ip = argv[i];
        if(test_records.find(ip) == test_records.end())
            ip_set.insert(ip);
        else
            printf("[DEBG] %s is tested before.\n", ip.c_str());
    }
    return 0;
}

void my_sqlite3_exec(char* sql){
    printf("[DEBG] SQL is: %s\n", sql);
    char *zErrMsg = 0;
    int rc = sqlite3_exec(result_db, sql, NULL, NULL, &zErrMsg);
    if( rc != SQLITE_OK ){
        printf("[ERRO] SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);

        printf("[ERRO] The execution backtrace is: \n");
        void * array[BACKTRACE_SIZE];
        int stack_num = backtrace(array, BACKTRACE_SIZE);
        char ** stacktrace = backtrace_symbols(array, stack_num);
        for (int i = 0; i < stack_num; ++i)
            printf("%s\n", stacktrace[i]);
        free(stacktrace);
        exit(-1);
    }
}

void my_sqlite3_alter(const char* name){
    std::string temp = "alter table infos add %s";
    size_t plt_len = temp.length() - 2 + strlen(name) + 1;
    char a_sql[plt_len];
    char *zErrMsg = 0;
    snprintf(a_sql, plt_len, temp.c_str(), name);
    // snprintf(a_sql, plt_len, "alter table infos add %s INTEGER default 1", name);
    printf("[DEBG] ALTER is: %s\n", a_sql);
    int rc = sqlite3_exec(result_db, a_sql, NULL, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
        printf("[WARN] SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }
}

int main(int argc, char **argv)
{
    bool need_help = false;
    for(int c = 1; c < argc; c++){
        if(strcmp(argv[c], "-s") == 0)
            single_thread = true;
        else if(strcmp(argv[c], "-pl") == 0){
            if(c == argc - 1){
                need_help = true;
                break;
            }
            char* pl_str = argv[c + 1];
            c++;
            pool_limit = atoi(pl_str);
            if(pool_limit == 0){
                need_help = true;
                break;
            }
        }
        else{
            need_help = true;
            break;
        }
    }
    if(need_help){
        printf("USAGE: ./rpc_scanner {-s} {-pl N}.\n");
        printf("-s: Single thread mode.\n");
        printf("-pl N: For multi-thread mode, limit the thread pool size to N.\n");
        exit(-1);
    }

    char* my_platform = DEFAULT_PLATFORM;
    printf("[INIT] Test on platform: %s.\n", my_platform);
    printf("[INIT] Test mode: %s.\n", single_thread ? "single thread" : "multiple threads");
    printf("[INIT] Test thread pool limit: %zu (Meaningless on single thread mode).\n", pool_limit);

    // prepare the test record file

    std::ifstream rec_fi(TESTED_RECORDS, std::ios::in);

    if(rec_fi) {
        std::string line;
        while(std::getline(rec_fi, line))
        {
            if(line.empty() || line.find("#") == 0)
                continue;

            test_records.insert(line);
        }
        rec_fi.close();
    }

    rec_fout.open(TESTED_RECORDS, std::ios::out | std::ios::app);
    if(!rec_fout.is_open()){
        printf("Cannot open ofstream for %s.\n", TESTED_RECORDS);
        exit(-1);
    }

    // query the ip list from NODEINFO_DATABASE database
    sqlite3 *db;
    int error;
    int rc = sqlite3_open(NODEINFO_DATABASE, &db);
    if( rc ){
        printf("[ERRO] Can't open database %s: %s\n", NODEINFO_DATABASE, sqlite3_errmsg(db));
        exit(-1);
    }
    char sql[] = "select distinct(IP) from nodeinfo";
    char *zErrMsg = 0;
    rc = sqlite3_exec(db, sql, nodeinfo_callback, NULL, &zErrMsg);
    if( rc != SQLITE_OK ){
        printf("[ERRO] SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        exit(-1);
    }
    sqlite3_close(db);

    // prepare for the PORTINFO_DATABASE database
    rc = sqlite3_open(PORTINFO_DATABASE, &result_db);
    if( rc ){
        printf("[ERRO] Can't open database %s: %s\n", PORTINFO_DATABASE, sqlite3_errmsg(result_db));
        exit(-1);
    }
    /* Create SQL statement */
    char c_sql[] = "create table if not exists infos (IP text, Port integer, NetID text, ChainID text, ClientType text, NodeType text, ClientVersion text, Architecture text, Language text, Accounts text, Hashrate text, Mining text, ProtocolVersion text);";
    my_sqlite3_exec(c_sql);

    std::string temp = "alter table infos add %s INTEGER default 1";
    size_t plt_len = temp.length() - 2 + strlen(my_platform) + 1;
    char a_sql[plt_len];
    snprintf(a_sql, plt_len, temp.c_str(), my_platform);
    rc = sqlite3_exec(result_db, a_sql, NULL, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
        printf("[WARN] SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }

    size_t ip_size = ip_set.size();
    printf("[INFO] Got %zu candidate IPs.\n", ip_size);

    // Initial the curl.
    /* Must initialize libcurl before any threads are started */
    CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
    if(res != CURLE_OK) {
        printf("[ERRO] url_global_init() failed: %s\n", curl_easy_strerror(res));
        return(-1);
    }

    hs = curl_slist_append(hs, "Content-Type: application/json");

    if(single_thread){
        for(std::string ip : ip_set) {
            size_t length = ip.length() + 1;
            char* ip_chars = (char*)malloc( length);
            memcpy(ip_chars, ip.c_str(), length);
            analyze_ip(ip_chars);
        }
    }
    else{
        size_t count = 0;
        // Create Analyzing Threads
        for(std::string ip : ip_set) {
            count++;
            size_t length = ip.length() + 1;
            char* ip_chars = (char*)malloc( length);
            memcpy(ip_chars, ip.c_str(), length);

            r_mtx.lock();
            test_pool.push_back(ip_chars);
            r_mtx.unlock();

            pthread_t pt;
            error = pthread_create(&pt, NULL, analyze_ip, (void *) ip_chars);
            if(error != 0){
                printf("[ERRO] Couldn't run thread number %zu, errno %d\n", count, error);
                exit(-1);
            }

            while(test_pool.size() >= pool_limit)
                usleep(1000 * 10); // 10 ms
        }
        /* now wait for all threads to terminate */
        while (test_pool.size() > 0) {
            usleep(1000 * 100); // 100ms
        }
    }


    // finish.
    curl_global_cleanup();
    sqlite3_close(result_db);
    rec_fout.close();
    return 0;
}

static void scan_candidate_ports(char* ip, std::set<int>& can_ports){
    size_t cmd_len = strlen(MASSCAN_CMD_MOD) + strlen(ip);
    char cmd_buf[cmd_len];
    sprintf(cmd_buf, MASSCAN_CMD_MOD, ip);

    FILE *fp = popen(cmd_buf, "r");
    if(!fp) {
        printf("[ERRO] [%s] popen error!", ip);
        exit(-1);
    }

    char buf[FGET_BUF_SIZE];
    while(true) {
        memset(buf, 0, FGET_BUF_SIZE);
        char* ret = fgets(buf, FGET_BUF_SIZE, fp);
        if(ret == NULL)
            break;
        size_t start_offset = strlen(FOUND_PORT_MARK);
        size_t len = 0;
        while(*(ret + start_offset + len) != '/')
            len++;
        assert(len > 0 && len <= 5);
        char pc[len + 1];
        memcpy(pc, ret + start_offset, len);
        pc[len] = 0;
        int p = atoi(pc);
        assert(p != 0);
        can_ports.insert(p);
    }
    pclose(fp);
}


// return socke_fd
int create_socket(struct sockaddr_in server_addr){
    // struct sockaddr_in server_addr;
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    while(socket_fd < 0){
        if(errno != 24){
            printf("[ERR] Create socket error: %s (errno:%d)\n", strerror(errno), errno);
            exit(0);
        }
        printf("[WRN] %s. We will create socket later...\n", strerror(errno));
        sleep(SOCKET_WAIT_TIME);
        socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    }

    int synRetries = 1; // 3 SYN packets ~= 7s
    int ret = setsockopt(socket_fd, IPPROTO_TCP, TCP_SYNCNT, &synRetries, sizeof(synRetries));
    if(ret == -1){
        printf("[ERR] Set socket option (TCP_SYNCNT) error: %s (errno:%d)\n", strerror(errno), errno);
        exit(0);
    }

    struct timeval timeout;
	timeout.tv_sec = CONN_TIMEOUT_SEC;
	timeout.tv_usec = 0;
    ret = setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if(ret == -1){
        printf("[ERR] Set socket option (SO_SNDTIMEO) error: %s (errno:%d)\n", strerror(errno), errno);
        exit(0);
    }

    struct timeval timeout2;
	timeout2.tv_sec = CONN_TIMEOUT_SEC;
	timeout2.tv_usec = 0;
    ret = setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout2, sizeof(timeout2));
    if(ret == -1){
        printf("[ERR] Set socket option (SO_RCVTIMEO) error: %s (errno:%d)\n", strerror(errno), errno);
        exit(0);
    }

    if(connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
#ifdef DEBUG
        std::string ip = inet_ntoa(server_addr.sin_addr);
        std::string address = ip + ":" + std::to_string(ntohs(server_addr.sin_port));
        std::string err_msg;
        if(errno == EINPROGRESS)
            err_msg = "connection timeout";
        else
            err_msg = strerror(errno);
        printf("\n[DBG] Connect %s error: %s (errno: %d).\n", address.c_str(), err_msg.c_str(), errno);
#endif
        close(socket_fd);
        return -1;
    }

    return socket_fd;
}

// Return true on successfully get some information and false on failed.
bool test_one_addr(char* ip, int port){
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &(server_addr.sin_addr));
    server_addr.sin_port = htons(port);
    int sock_fd = create_socket(server_addr);
    if(sock_fd == -1){
        printf("[DEBG] [%s:%d] is not connectable.\n", ip, port);
        return false;
    }
    close(sock_fd);

    printf("[INFO] [%s:%d] is connectable.\n", ip, port);

    size_t len = strlen(ip) + strlen("http://%s:%d") + 5;  // 5 is the max length of a port
    char url[len];
    snprintf(url, len, "http://%s:%d", ip, port);

    std::stringstream rstream;

    /* get a curl handle */
    CURL *curl = curl_easy_init();
    if(curl == NULL){
        printf("[ERRO]] curl_easy_init() failed.\n");
        curl_easy_cleanup(curl);
        exit(-1);
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rstream);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hs);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, TIMEOUT);
    AQRESULT account_results = Empty;
    // return true means connectable
    if(!web3_clientVersion(curl, ip, port, url, rstream))
        goto cleanup;
    if(!net_version(curl, ip, port, url, rstream))
        goto cleanup;
    if(!eth_hashrate(curl, ip, port, url, rstream))
        goto cleanup;
    if(!rpc_modules(curl, ip, port, url, rstream))
        goto cleanup;
    if(!eth_mining(curl, ip, port, url, rstream))
        goto cleanup;
    if(!eth_protocolVersion(curl, ip, port, url, rstream))
        goto cleanup;
    if(!parity_chainId(curl, ip, port, url, rstream))
        goto cleanup;

    account_results = eth_accounts(curl, ip, port, url, rstream);
    if(account_results == Failed)
        goto cleanup;

    if(account_results == Empty)
        account_results =  parity_allAccountsInfo(curl, ip, port, url, rstream);

    if(account_results == Failed)
        goto cleanup;

    if(account_results == Empty)
        account_results = personal_listAccounts(curl, ip, port, url, rstream);

    if(account_results == Failed)
        goto cleanup;

    return true;

cleanup:
    curl_easy_cleanup(curl);
    return false;

}

static void * analyze_ip(void* data){
    if(!single_thread)
        pthread_detach(pthread_self());
    char* ip = (char*) data;
    printf("[DEBG] [%s] Analyzing begin.\n", ip);

    bool success = test_one_addr(ip, 8545);
    if(!success){ // We need to do the all port scan work
        std::set<int> can_ports;
        scan_candidate_ports(ip, can_ports);
        if(can_ports.size() > 0){
            char buf[128];
            sprintf(buf, "[INFO] [%s] Found %lu ports: ", ip, can_ports.size());
            for(int p : can_ports)
                sprintf(buf, "%s %d ", buf, p);
            printf("%s.\n", buf);

            for(int port : can_ports){
                success = test_one_addr(ip, port);
                if(success)
                    break;
            }
        }
        else
            printf("[DEBG] [%s] Opened no ports.\n", ip);
    }

    if(!single_thread)
        r_mtx.lock();

    rec_fout << std::string(ip) << std::endl;
    rec_fout.flush();

    if(!single_thread){
        test_pool.remove(ip);
        r_mtx.unlock();
    }
    free(ip);

    return NULL;
}


bool net_version(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream){
    /* Perform the request, res will get the return code */

    static const char data[]="{\"jsonrpc\":\"2.0\",\"method\":\"net_version\",\"params\":[],\"id\":233}";
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    CURLcode res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK){
        printf("[INFO] [%s:%d] Connection Failed: %s.\n", ip, port, curl_easy_strerror(res));
        return false;
    }
    std::string str_json = rstream.str();
    rstream.str("");

    rapidjson::Document doc;
    doc.Parse(str_json.c_str());
    if(doc.IsObject()){
        if(doc.HasMember("result")){
            rapidjson::Value& result = doc["result"];
            if(result.IsNull())
                return true;
            std::string netid = doc["result"].GetString();
            printf("[INFO] [%s:%d] Net ID: %s.\n", ip, port, netid.c_str());
            if(checkAddrExist(ip, port)){
                std::string temp = "update infos set NetID = \"%s\" where IP = \"%s\" and Port = %d";
                size_t len = temp.length() + netid.length() + strlen(ip) + 5;
                char sql[len];
                snprintf(sql, len, temp.c_str(), netid.c_str(), ip, port);
                my_sqlite3_exec(sql);
            }
            else{
                std::string temp = "insert into infos (IP, NetID, Port) values (\"%s\", \"%s\", %d)";
                size_t len = temp.length() + netid.length() + strlen(ip) + 5;
                char sql[len];
                snprintf(sql, len, temp.c_str(), ip, netid.c_str(), port);
                my_sqlite3_exec(sql);
            }
        }
    }
    else
        printf("[WARN] [%s:%d] net_version's result cannot be parsed.\n", ip, port);
    return true;
}

bool web3_clientVersion(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream){
    /* Perform the request, res will get the return code */
    static const char data[]="{\"jsonrpc\":\"2.0\",\"method\":\"web3_clientVersion\",\"params\":[],\"id\":233}";
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    CURLcode res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK){
        printf("[INFO] [%s:%d] Connection Failed: %s.\n", ip, port, curl_easy_strerror(res));
        return false;
    }
    std::string str_json = rstream.str();
    rstream.str("");

    rapidjson::Document doc;
    doc.Parse(str_json.c_str());
    if(doc.IsObject()){
        if(doc.HasMember("result")){
            rapidjson::Value& result = doc["result"];
            if(result.IsNull())
                return true;
            std::string cltver = result.GetString();
            // printf("[INFO] [%s] Client Version: %s.\n", ip, cltver.c_str());
            std::string cltType;
            std::string nodeType;
            std::string cv;
            std::string arch;
            std::string lang;
            size_t valid = 0;
            size_t begin = 0;
            bool finish = false;
            while(!finish){
                size_t end = cltver.find("/", begin);
                if(end == std::string::npos){
                    end = cltver.length();
                    finish = true;
                }
                std::string ss = cltver.substr(begin, end - begin);
                begin = end + 1;

                if(ss.length() == 0)
                    continue;

                switch (valid){
                    case 0:
                        cltType = ss;
                        printf("[INFO] [%s:%d] Client Type: %s.\n", ip, port, cltType.c_str());
                        break;
                    case 1:
                        if(ss.c_str()[0] != 'v'){
                            nodeType = ss;
                            printf("[INFO] [%s:%d] Node Type: %s.\n", ip, port, nodeType.c_str());
                            continue;
                        }
                        cv = ss;
                        printf("[INFO] [%s:%d] Client Version: %s.\n", ip, port, cv.c_str());
                        break;
                    case 2:
                        arch = ss;
                        printf("[INFO] [%s:%d] Client Architecture: %s.\n", ip, port, arch.c_str());
                        break;
                    case 3:
                        lang = ss;
                        printf("[INFO] [%s:%d] Client Launguage: %s.\n", ip, port, lang.c_str());
                        break;
                    default:
                        printf("[WARN] [%s:%d] Strange client version string: %s.\n", ip, port, cltver.c_str());
                }
                valid++;
            }

            if(checkAddrExist(ip, port)){
                std::string temp = "update infos set ClientType = \"%s\", NodeType = \"%s\", ClientVersion = \"%s\", Architecture = \"%s\", Language = \"%s\" where IP = \"%s\" and Port = %d";

                size_t len = temp.length() + cltType.length() + nodeType.length() + cv.length() + arch.length() + lang.length() + strlen(ip) + 5;
                char sql[len];
                snprintf(sql, len, temp.c_str(), cltType.c_str(), nodeType.c_str(), cv.c_str(), arch.c_str(), lang.c_str(), ip, port);
                my_sqlite3_exec(sql);
            }
            else{
                std::string temp = "insert into infos (IP, ClientType, NodeType, ClientVersion, Architecture, Language, Port) values (\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", %d)";

                size_t len = temp.length() + cltType.length() + nodeType.length() + cv.length() + arch.length() + lang.length() + strlen(ip) + 5;
                char sql[len];
                snprintf(sql, len, temp.c_str(), ip, cltType.c_str(), nodeType.c_str(), cv.c_str(), arch.c_str(), lang.c_str(), port);
                my_sqlite3_exec(sql);
            }
        }
    }
    else
        printf("[WARN] [%s:%d] web3_clientVersion's result cannot be parsed.\n", ip, port);
    return true;
}

bool eth_hashrate(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream){
    /* Perform the request, res will get the return code */
    static const char data[]="{\"jsonrpc\":\"2.0\",\"method\":\"eth_hashrate\",\"params\":[],\"id\":233}";
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    CURLcode res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK){
        printf("[INFO] [%s:%d] Connection Failed: %s.\n", ip, port, curl_easy_strerror(res));
        return false;
    }
    std::string str_json = rstream.str();
    rstream.str("");
    rapidjson::Document doc;
    doc.Parse(str_json.c_str());
    if(doc.IsObject()){
        if(doc.HasMember("result")){
            rapidjson::Value& result = doc["result"];
            if(result.IsNull())
                return true;
            std::string hr = result.GetString();
            printf("[INFO] [%s:%d] Hash Rate: %s.\n", ip, port, hr.c_str());
            if(checkAddrExist(ip, port)){
                std::string temp = "update infos set Hashrate = \"%s\" where IP = \"%s\" and Port = %d";
                size_t len = temp.length() + hr.length() + strlen(ip) + 5;
                char sql[len];
                snprintf(sql, len, temp.c_str(), hr.c_str(), ip);
                my_sqlite3_exec(sql);
            }
            else{
                std::string temp = "insert into infos (IP, Hashrate, Port) values (\"%s\", \"%s\", %d)";
                size_t len = temp.length() + hr.length() + strlen(ip) + 5;
                char sql[len];
                snprintf(sql, len, temp.c_str(), ip, hr.c_str(), port);
                my_sqlite3_exec(sql);
            }
        }
    }
    else
        printf("[WARN] [%s:%d] eth_hashrate's result cannot be parsed.\n", ip, port);
    return true;
}

bool rpc_modules(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream){
    /* Perform the request, res will get the return code */
    static const char data[]="{\"jsonrpc\":\"2.0\",\"method\":\"rpc_modules\",\"params\":[],\"id\":233}";
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    CURLcode res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK){
        printf("[INFO] [%s:%d] Connection Failed: %s.\n", ip, port,curl_easy_strerror(res));
        return false;
    }
    std::string str_json = rstream.str();
    rstream.str("");
    rapidjson::Document doc;
    doc.Parse(str_json.c_str());
    if(doc.IsObject()){
        if(doc.HasMember("result")){
            rapidjson::Value& result = doc["result"];
            if(result.IsNull())
                return false;
            for (rapidjson::Value::ConstMemberIterator itr = result.MemberBegin(); itr != result.MemberEnd(); ++itr){
                std::string name = itr->name.GetString();
                std::string value = itr->value.GetString();
                printf("[INFO] [%s:%d] RPC module: %s - %s.\n", ip, port, name.c_str(), value.c_str());

                // alter new colomn
                my_sqlite3_alter(name.c_str());
                if(checkAddrExist(ip, port)){
                    std::string temp = "update infos set %s = \"%s\" where IP = \"%s\" and Port = %d";
                    size_t len = temp.length() + name.length() + value.length() + strlen(ip) + 5;
                    char sql[len];
                    snprintf(sql, len, temp.c_str(), name.c_str(), value.c_str(), ip, port);
                    my_sqlite3_exec(sql);
                }
                else{
                    std::string temp = "insert into infos (IP, %s, Port) values (\"%s\", \"%s\", %d)";
                    size_t len = temp.length() + name.length() + value.length() + strlen(ip) + 5;
                    char sql[len];
                    snprintf(sql, len, temp.c_str(), name.c_str(), ip, value.c_str(), port);
                    my_sqlite3_exec(sql);
                }
            }
        }
    }
    else
        printf("[WARN] [%s:%d] rpc_modules's result cannot be parsed.\n", ip, port);
    return true;
}

bool eth_mining(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream){
    /* Perform the request, res will get the return code */
    static const char data[]="{\"jsonrpc\":\"2.0\",\"method\":\"eth_mining\",\"params\":[],\"id\":233}";
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    CURLcode res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK){
        printf("[INFO] [%s:%d] Connection Failed: %s.\n", ip, port, curl_easy_strerror(res));
        return false;
    }
    std::string str_json = rstream.str();
    rstream.str("");
    rapidjson::Document doc;
    doc.Parse(str_json.c_str());
    if(doc.IsObject()){
        if(doc.HasMember("result")){
            rapidjson::Value& result = doc["result"];
            if(result.IsNull())
                return true;
            std::string im = result.GetBool() ? "True" : "False";
            printf("[INFO] [%s:%d] Eth mining: %s.\n", ip, port, im.c_str());
            if(checkAddrExist(ip, port)){
                std::string temp = "update infos set Mining = \"%s\" where IP = \"%s\" and Port = %d";
                size_t len = temp.length() + im.length() + strlen(ip) + 5;
                char sql[len];
                snprintf(sql, len, temp.c_str(), im.c_str(), ip, port);
                my_sqlite3_exec(sql);
            }
            else{
                std::string temp = "insert into infos (IP, Mining, Port) values (\"%s\", \"%s\", %d)";
                size_t len = temp.length() + im.length() + strlen(ip) + 5;
                char sql[len];
                snprintf(sql, len, temp.c_str(), ip, im.c_str(), port);
                my_sqlite3_exec(sql);
            }
        }
    }
    else
        printf("[WARN] [%s:%d] eth_mining's result cannot be parsed.\n", ip, port);
    return true;
}

bool eth_protocolVersion(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream){
    /* Perform the request, res will get the return code */
    static const char data[]="{\"jsonrpc\":\"2.0\",\"method\":\"eth_protocolVersion\",\"params\":[],\"id\":233}";
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    CURLcode res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK){
        printf("[INFO] [%s:%d] Connection Failed: %s.\n", ip, port, curl_easy_strerror(res));
        return false;
    }
    std::string str_json = rstream.str();
    rstream.str("");
    rapidjson::Document doc;
    doc.Parse(str_json.c_str());
    if(doc.IsObject()){
        if(doc.HasMember("result")){
            rapidjson::Value& result = doc["result"];
            if(result.IsNull())
                return true;
            std::string pv = result.GetString();
            printf("[INFO] [%s:%d] Protocol version: %s.\n", ip, port, pv.c_str());
            if(checkAddrExist(ip, port)){
                std::string temp = "update infos set ProtocolVersion = \"%s\" where IP = \"%s\" and Port = %d";
                size_t len = temp.length() + pv.length() + strlen(ip) + 5;
                char sql[len];
                snprintf(sql, len, temp.c_str(), pv.c_str(), ip, port);
                my_sqlite3_exec(sql);
            }
            else{
                std::string temp = "insert into infos (IP, ProtocolVersion, Port) values (\"%s\", \"%s\", %d)";
                size_t len = temp.length() + pv.length() + strlen(ip) + 5;
                char sql[len];
                snprintf(sql, len, temp.c_str(), ip, pv.c_str(), port);
                my_sqlite3_exec(sql);
            }
        }
    }
    else
        printf("[WARN] [%s:%d] eth_protocolVersion's result cannot be parsed.\n", ip, port);
    return true;
}

bool parity_chainId(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream){
    /* Perform the request, res will get the return code */
    static const char data[]="{\"jsonrpc\":\"2.0\",\"method\":\"parity_chainId\",\"params\":[],\"id\":233}";
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    CURLcode res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK){
        printf("[INFO] [%s:%d] Connection Failed: %s.\n", ip, port, curl_easy_strerror(res));
        return false;
    }
    std::string str_json = rstream.str();
    rstream.str("");
    rapidjson::Document doc;
    doc.Parse(str_json.c_str());
    if(doc.IsObject()){
        if(doc.HasMember("result")){
            rapidjson::Value& result = doc["result"];
            if(result.IsNull())
                return true;
            std::string cid = result.GetString();
            printf("[INFO] [%s:%d] Parity ChainID: %s.\n", ip, port, cid.c_str());
            if(checkAddrExist(ip, port)){
                std::string temp = "update infos set ChainID = \"%s\" where IP = \"%s\" and Port = %d";
                size_t len = temp.length() + cid.length() + strlen(ip) + 5;
                char sql[len];
                snprintf(sql, len, temp.c_str(), cid.c_str(), ip, port);
                my_sqlite3_exec(sql);
            }
            else{
                std::string temp = "insert into infos (IP, ChainID, Port) values (\"%s\", \"%s\", %d)";
                size_t len = temp.length() + cid.length() + strlen(ip) + 5;
                char sql[len];
                snprintf(sql, len, temp.c_str(), ip, cid.c_str(), port);
                my_sqlite3_exec(sql);
            }
        }
    }
    else
        printf("[WARN] [%s:%d] parity_chainId's result cannot be parsed.\n", ip, port);
    return true;
}

void record_account(const char* ip, int port, const char* acts){
    if(checkAddrExist(ip, port)){
        std::string temp = "update infos set Accounts = \"%s\" where IP = \"%s\" and Port = %d";
        size_t len = temp.length() + strlen(acts) + strlen(ip) + 5;
        char sql[len];
        snprintf(sql, len, temp.c_str(), acts, ip, port);
        my_sqlite3_exec(sql);
    }
    else{
        std::string temp = "insert into infos (IP, Accounts, Port) values (\"%s\", \"%s\", %d)";
        size_t len = temp.length() + strlen(acts) + strlen(ip) + 5;
        char sql[len];
        snprintf(sql, len, temp.c_str(), ip, acts, port);
        my_sqlite3_exec(sql);
    }
}

AQRESULT eth_accounts(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream){
    /* Perform the request, res will get the return code */
    static const char data[]="{\"jsonrpc\":\"2.0\",\"method\":\"eth_accounts\",\"params\":[],\"id\":233}";
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    CURLcode res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK){
        printf("[INFO] [%s:%d] Connection Failed: %s.\n", ip, port, curl_easy_strerror(res));
        return Failed;
    }
    std::string str_json = rstream.str();
    rstream.str("");
    rapidjson::Document doc;
    doc.Parse(str_json.c_str());
    if(doc.IsObject()){
        if(doc.HasMember("result")){
            rapidjson::Value& result = doc["result"];
            if(result.IsNull())
                return Empty;
            std::string acts = "";
            for (auto& v : doc["result"].GetArray()){
                std::string ac = v.GetString();
                acts = acts + ", " + ac;
            }
            if(acts.length() > 2){
                acts = "[EA] " + acts.substr(2);
                printf("[INFO] [%s] Accounts: %s.\n", ip, acts.c_str());
                record_account(ip, port, acts.c_str());
                return Success;
            }
        }
    }
    else
        printf("[WARN] [%s:%d] eth_accounts's result cannot be parsed.\n", ip, port);
    return Failed;
}

AQRESULT parity_allAccountsInfo(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream){
    /* Perform the request, res will get the return code */
    static const char data[]="{\"jsonrpc\":\"2.0\",\"method\":\"parity_allAccountsInfo\",\"params\":[],\"id\":233}";
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    CURLcode res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK){
        printf("[INFO] [%s:%d] Connection Failed: %s.\n", ip, port, curl_easy_strerror(res));
        return Failed;
    }
    std::string str_json = rstream.str();
    rstream.str("");
    rapidjson::Document doc;
    doc.Parse(str_json.c_str());

    if(doc.IsObject()){
        if(doc.HasMember("result")){
            std::string acts = "";
            rapidjson::Value& result = doc["result"];
            if(result.IsNull())
                return Empty;
            for (rapidjson::Value::ConstMemberIterator itr = result.MemberBegin(); itr != result.MemberEnd(); ++itr){
                std::string ac = itr->name.GetString();
                acts = acts + ", " + ac;
            }
            if(acts.length() > 2){
                acts = "[PA] " + acts.substr(2);
                record_account(ip, port, acts.c_str());
                printf("[INFO] [%s:%d] Accounts: %s.\n", ip, port, acts.c_str());
                return Success;
            }
        }
    }
    else
        printf("[WARN] [%s:%d] parity_allAccountsInfo's result cannot be parsed.\n", ip, port);
    return Failed;
}

AQRESULT personal_listAccounts(CURL *curl, char const * ip, int port, char* url, std::stringstream& rstream){
    /* Perform the request, res will get the return code */
    static const char data[]="{\"jsonrpc\":\"2.0\",\"method\":\"personal_listAccounts\",\"params\":[],\"id\":233}";
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    CURLcode res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK){
        printf("[INFO] [%s:%d] Connection Failed: %s.\n", ip, port, curl_easy_strerror(res));
        return Failed;
    }
    std::string str_json = rstream.str();
    rstream.str("");
    rapidjson::Document doc;
    doc.Parse(str_json.c_str());
    if(doc.IsObject()){
        if(doc.HasMember("result")){
            rapidjson::Value& result = doc["result"];
            if(result.IsNull())
                return Empty;
            std::string acts = "";
            for (auto& v : result.GetArray()){
                std::string ac = v.GetString();
                acts = acts + ", " + ac;
            }
            if(acts.length() > 2){
                acts = "[PL] " + acts.substr(2);
                record_account(ip, port, acts.c_str());
                printf("[INFO] [%s:%d] Accounts: %s.\n", ip, port, acts.c_str());
                return Success;
            }
        }
    }
    else
        printf("[WARN] [%s:%d] personal_listAccounts's result cannot be parsed.\n", ip, port);
    return Failed;
}


static int check_ip_callback(void *data, int argc, char **argv, char **azColName){
    bool* exist = (bool*) data;
    *exist = true;
    return 0;
}

#define SELECT_MOD "select * from infos where IP = \"%s\" and Port = %d"
bool checkAddrExist(char const * ip, int port){
    size_t buf_len = strlen(SELECT_MOD) + strlen(ip) + 5;
    char sql[buf_len];
    sprintf(sql, SELECT_MOD, ip, port);

    char *zErrMsg = 0;
    bool result = false;
    int rc = sqlite3_exec(result_db, sql, check_ip_callback, (void*)&result, &zErrMsg);
    if( rc != SQLITE_OK ){
        printf("SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        exit(-1);
    }
    return result;
}