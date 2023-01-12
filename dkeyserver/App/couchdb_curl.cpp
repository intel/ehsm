#include "couchdb_curl.h"

using namespace std;

size_t getUrlResponse(void *buffer, size_t size, size_t count, void *response)
{
    string *str = (string *)response;
    (*str).append((char *)buffer, size * count);

    return size * count;
}

string setRequest(string url, string data)
{
    string response = "";

    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();

    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "charsets: utf-8");

    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());

    //    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    //    curl_easy_setopt(curl, CURLOPT_HEADER, 0L);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &getUrlResponse);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    int res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return response;
}

string getRequest(string url)
{
    string response = "";

    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();

    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "charsets: utf-8");

    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &getUrlResponse);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    curl_easy_perform(curl);

    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return response;
}

void print_json(JsonValue data, vector<string> &keylist, string req_data)
{
    JsonValue::Members mem = data.getMemberNames();

    for (auto iter = mem.begin(); iter != mem.end(); iter++)
    {
        if (data[*iter].type() == Json::objectValue)
        {
            print_json(data[*iter], keylist, req_data);
        }
        else if (data[*iter].type() == Json::arrayValue)
        {
            auto cnt = data[*iter].size();
            for (auto i = 0; i < cnt; i++)
            {
                print_json(data[*iter][i], keylist, req_data);
            }
        }
        else if (data[*iter].type() == Json::stringValue)
        {
            string str = data[*iter].asString();
            if (string::npos != str.find(req_data))
                if (keylist.at(keylist.size() - 1).compare(data[*iter].asString()))
                    keylist.push_back(data[*iter].asString());
        }
    }
}

int couchdb_get(vector<JsonObj> &data, string req_data, string url)
{
    auto res = getRequest(url + "/ehsm_kms_db/_all_docs");

    JsonReader reader;
    JsonValue value;
    if (!reader.parse(res, value))
        return -1;

    vector<string> _ids;
    _ids.push_back("");
    print_json(value, _ids, req_data);
    _ids.erase(_ids.begin());

    for (auto id : _ids)
    {
        auto res = getRequest(url + "/ehsm_kms_db/" + id);
        JsonObj temp;
        temp.parse(res);
        cout<<"couchdb_get in="<<temp.toString().c_str()<<endl;
        data.push_back(temp);
    }

    return data.size();
}

int couchdb_put(JsonObj data, string url)
{
    string js_data = data.toString();
    cout<<"couchdb_put in="<<js_data.c_str()<<endl;
    string res = setRequest(url + "/ehsm_kms_db/" + data.readData_string("_id"), js_data);

    if (string::npos != res.find("\"ok\""))
        return 1;
    else
        return -1;
}