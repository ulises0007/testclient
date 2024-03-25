#include <iostream>
#include <string>
#include <chrono>
#include <jwt-cpp/jwt.h>
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sqlite3.h>

using namespace std;

string bignum_to_raw_string(const BIGNUM *bn)
{
    int bn_size = BN_num_bytes(bn);
    string raw(bn_size, 0);
    BN_bn2bin(bn, reinterpret_cast<unsigned char *>(&raw[0]));
    return raw;
}

string extract_pub_key(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    string result(data, len);
    BIO_free(bio);
    return result;
}

string extract_priv_key(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    string result(data, len);
    BIO_free(bio);
    return result;
}

string base64_url_encode(const string &data)
{
    static const string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (size_t n = 0; n < data.size(); n++)
    {
        char_array_3[i++] = data[n];
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];
    }

    // Replace '+' with '-', '/' with '_' and remove '='
    replace(ret.begin(), ret.end(), '+', '-');
    replace(ret.begin(), ret.end(), '/', '_');
    ret.erase(remove(ret.begin(), ret.end(), '='), ret.end());

    return ret;
}

int main()
{
    // Initialize SQLite database and create the 'keys' table
    sqlite3 *db;
    int rc = sqlite3_open("totally_not_my_privateKeys.db", &db);
    if (rc != SQLITE_OK)
    {
        cerr << "Error opening SQLite database: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return 1;
    }

    const char *create_table_sql =
        "CREATE TABLE IF NOT EXISTS keys("
        "kid INTEGER PRIMARY KEY AUTOINCREMENT,"
        "key TEXT NOT NULL,"
        "exp INTEGER NOT NULL"
        ")";
    rc = sqlite3_exec(db, create_table_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK)
    {
        cerr << "Error creating keys table: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return 1;
    }

    // Start HTTP server
    httplib::Server svr;

    svr.Post("/auth", [&](const httplib::Request &req, httplib::Response &res)
             {
                 if (req.method != "POST")
                 {
                     res.status = 405; // Method Not Allowed
                     res.set_content("Method Not Allowed", "text/plain");
                     return;
                 }
                 // Check if the "expired" query parameter is set to "true"
                 bool expired = req.has_param("expired") && req.get_param_value("expired") == "true";

                 // Read private key from the database
                 sqlite3_stmt *stmt;
                 const char *select_key_sql = "SELECT key FROM keys WHERE exp > ? LIMIT 1";
                 rc = sqlite3_prepare_v2(db, select_key_sql, -1, &stmt, NULL);
                 if (rc != SQLITE_OK)
                 {
                     cerr << "Error preparing SQL statement: " << sqlite3_errmsg(db) << endl;
                     sqlite3_finalize(stmt);
                     sqlite3_close(db);
                     return;
                 }

                 sqlite3_bind_int(stmt, 1, expired ? 0 : std::time(nullptr));

                 rc = sqlite3_step(stmt);
                 if (rc != SQLITE_ROW)
                 {
                     cerr << "Error retrieving key from database: " << sqlite3_errmsg(db) << endl;
                     sqlite3_finalize(stmt);
                     sqlite3_close(db);
                     return;
                 }

                 string priv_key_str = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));

                 // Create JWT token
                 auto now = chrono::system_clock::now();
                 auto token = jwt::create()
                                  .set_issuer("auth0")
                                  .set_type("JWT")
                                  .set_payload_claim("sample", jwt::claim(string("test")))
                                  .set_issued_at(chrono::system_clock::now())
                                  .set_expires_at(expired ? now - chrono::seconds{1} : now + chrono::hours{24})
                                  .set_key_id(expired ? "expiredKID" : "goodKID")
                                  .sign(jwt::algorithm::rs256(priv_key_str, priv_key_str));

                 res.set_content(token, "text/plain");
             });

    svr.Get("/.well-known/jwks.json", [&](const httplib::Request &, httplib::Response &res)
            {
                sqlite3_stmt
