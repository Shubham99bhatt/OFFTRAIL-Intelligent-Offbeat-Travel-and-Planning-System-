/* OFFTRAIL minimal C HTTP API server (Windows Winsock / POSIX sockets).
 * Configure MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE in environment.
 * Build with MariaDB Connector/C or MySQL client library. */
#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib,"Ws2_32.lib")
typedef SOCKET socket_t;
#define CLOSESOCK closesocket
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define CLOSESOCK close
#endif
#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <time.h>
#include "os_api.h"
#ifndef _WIN32
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <unistd.h>
#endif

#define USER_PORT 5000
static int SERVER_PORT=USER_PORT;
static int OWNER_MODE=0;
#define ROOT "../../frontend"
#define REQ_CAP 1600000
#define WORKER_COUNT 4
#define REQUEST_QUEUE_CAP 64
#ifdef _MSC_VER
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL _Thread_local
#endif
/* Connector/C connections are per worker: MYSQL handles are never shared. */
static THREAD_LOCAL MYSQL *db=NULL;
/* One server process accepts sockets into a bounded FCFS queue. Worker threads
 * dequeue requests concurrently; the queue lock/conditions protect shared state. */
static socket_t request_queue[REQUEST_QUEUE_CAP];
static int request_head=0,request_tail=0,request_count=0,active_workers=0;
static unsigned long long requests_accepted=0,requests_completed=0;
static int worker_busy[WORKER_COUNT]={0};
static void handle(socket_t c);
static int receive_http_request(socket_t c,char *req);
static void json_string(char *out,size_t cap,size_t *used,const char *s);
#ifdef _WIN32
static CRITICAL_SECTION request_lock;
static CONDITION_VARIABLE request_ready,queue_space;
#else
static pthread_mutex_t request_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t request_ready=PTHREAD_COND_INITIALIZER,queue_space=PTHREAD_COND_INITIALIZER;
#endif
static int secure_random(unsigned char *out,size_t n){
#ifdef _WIN32
 return BCryptGenRandom(NULL,out,(ULONG)n,BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0;
#else
 return RAND_bytes(out,(int)n)==1;
#endif
}
static int derive_password(const char *password,const unsigned char *salt,size_t salt_n,unsigned char *out,size_t out_n){
#ifdef _WIN32
 BCRYPT_ALG_HANDLE alg=NULL;NTSTATUS s=BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,NULL,BCRYPT_ALG_HANDLE_HMAC_FLAG);if(s<0)return 0;s=BCryptDeriveKeyPBKDF2(alg,(PUCHAR)password,(ULONG)strlen(password),(PUCHAR)salt,(ULONG)salt_n,600000,out,(ULONG)out_n,0);BCryptCloseAlgorithmProvider(alg,0);return s>=0;
#else
 return PKCS5_PBKDF2_HMAC(password,(int)strlen(password),salt,(int)salt_n,600000,EVP_sha256(),(int)out_n,out)==1;
#endif
}
static int sha256(const unsigned char *in,size_t n,unsigned char *out){
#ifdef _WIN32
 BCRYPT_ALG_HANDLE alg=NULL;BCRYPT_HASH_HANDLE hash=NULL;NTSTATUS s=BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,NULL,0);if(s<0)return 0;s=BCryptCreateHash(alg,&hash,NULL,0,NULL,0,0);if(s>=0)s=BCryptHashData(hash,(PUCHAR)in,(ULONG)n,0);if(s>=0)s=BCryptFinishHash(hash,out,32,0);if(hash)BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(alg,0);return s>=0;
#else
 unsigned int written=0;return EVP_Digest(in,n,out,&written,EVP_sha256(),NULL)==1&&written==32;
#endif
}
static void send_response(socket_t c,const char *status,const char *type,const char *body){char h[1024];size_t n=strlen(body);int k=snprintf(h,sizeof h,"HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Content-Type, Authorization\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n",status,type,n);send(c,h,k,0);send(c,body,(int)n,0);}
static void json_error(socket_t c,const char *msg){char b[512];snprintf(b,sizeof b,"{\"error\":\"%s\"}",msg);send_response(c,"500 Internal Server Error","application/json; charset=utf-8",b);}
static void auth_reply(socket_t c,const char *status,const char *body){send_response(c,status,"application/json; charset=utf-8",body);}
static int hex_encode(const unsigned char *in,size_t n,char *out,size_t cap){static const char h[]="0123456789abcdef";if(cap<n*2+1)return 0;for(size_t i=0;i<n;i++){out[i*2]=h[in[i]>>4];out[i*2+1]=h[in[i]&15];}out[n*2]=0;return 1;}
static int hex_decode(const char *in,unsigned char *out,size_t n){if(strlen(in)!=n*2)return 0;for(size_t i=0;i<n;i++){char a=(char)tolower((unsigned char)in[i*2]),b=(char)tolower((unsigned char)in[i*2+1]);int x=(a>='0'&&a<='9')?a-'0':(a>='a'&&a<='f')?a-'a'+10:-1;int y=(b>='0'&&b<='9')?b-'0':(b>='a'&&b<='f')?b-'a'+10:-1;if(x<0||y<0)return 0;out[i]=(unsigned char)((x<<4)|y);}return 1;}
static int json_field(const char *body,const char *key,char *out,size_t cap){char needle[80];snprintf(needle,sizeof needle,"\"%s\"",key);const char *p=strstr(body,needle);if(!p)return 0;p=strchr(p+strlen(needle),':');if(!p)return 0;p++;while(*p&&isspace((unsigned char)*p))p++;if(*p!='\"')return 0;p++;size_t n=0;while(*p&&*p!='\"'&&n+1<cap){if(*p=='\\'&&p[1])p++;if((unsigned char)*p<32)return 0;out[n++]=*p++;}if(*p!='\"')return 0;out[n]=0;return 1;}
static int password_ok(const char *p){int upper=0,digit=0,special=0;if(strlen(p)<8)return 0;for(const unsigned char *q=(const unsigned char*)p;*q;q++){upper|=isupper(*q);digit|=isdigit(*q);special|=(!isalnum(*q));}return isupper((unsigned char)p[0])&&upper&&digit&&special;}
static int make_hash(const char *password,char *out,size_t cap){unsigned char salt[16],hash[32];char sh[33],hh[65];if(!secure_random(salt,sizeof salt)||!derive_password(password,salt,sizeof salt,hash,sizeof hash))return 0;hex_encode(salt,sizeof salt,sh,sizeof sh);hex_encode(hash,sizeof hash,hh,sizeof hh);return snprintf(out,cap,"pbkdf2_sha256$600000$%s$%s",sh,hh)<(int)cap;}
static int check_hash(const char *password,const char *stored){char salt_s[33],hash_s[65],extra;unsigned char salt[16],expected[32],actual[32];int rounds=0;if(sscanf(stored,"pbkdf2_sha256$%d$%32[0-9a-fA-F]$%64[0-9a-fA-F]%c",&rounds,salt_s,hash_s,&extra)!=3||rounds!=600000||!hex_decode(salt_s,salt,sizeof salt)||!hex_decode(hash_s,expected,sizeof expected)||!derive_password(password,salt,sizeof salt,actual,sizeof actual))return 0;unsigned char diff=0;for(size_t i=0;i<sizeof actual;i++)diff|=actual[i]^expected[i];return diff==0;}
static void auth_post(socket_t c,const char *path,const char *body){char username[41],email[255],password[256],norm[41],hash[128],token[65],token_hash[65],response[512];if(!db){auth_reply(c,"503 Service Unavailable","{\"error\":\"Database unavailable. Start MySQL/MariaDB and configure the database first.\"}");return;}if(!json_field(body,"username",username,sizeof username)||!json_field(body,"password",password,sizeof password)){auth_reply(c,"400 Bad Request","{\"error\":\"Username and password are required.\"}");return;}if(strlen(username)<3||strlen(username)>40){auth_reply(c,"400 Bad Request","{\"error\":\"Username must be 3 to 40 characters.\"}");return;}for(size_t i=0;username[i];i++){if(!isalnum((unsigned char)username[i])&&username[i]!='_'&&username[i]!='-'){auth_reply(c,"400 Bad Request","{\"error\":\"Username can use letters, numbers, underscore and hyphen.\"}");return;}norm[i]=(char)tolower((unsigned char)username[i]);}norm[strlen(username)]=0;
 if(!strcmp(path,"/api/auth/signup")){if(!json_field(body,"email",email,sizeof email)||strlen(email)<6||!strchr(email,'@')||!strchr(strchr(email,'@')+1,'.')){auth_reply(c,"400 Bad Request","{\"error\":\"Enter a valid email address.\"}");return;}if(!password_ok(password)){auth_reply(c,"400 Bad Request","{\"error\":\"Password must be 8+ characters, start with uppercase, and include a number and special character.\"}");return;}if(!make_hash(password,hash,sizeof hash)){auth_reply(c,"500 Internal Server Error","{\"error\":\"Could not securely process password.\"}");return;}MYSQL_STMT *st=mysql_stmt_init(db);const char *q="INSERT INTO users(username,username_normalized,email,password_hash,is_active) VALUES(?,?,?,?,TRUE)";if(!st||mysql_stmt_prepare(st,q,(unsigned long)strlen(q))){if(st)mysql_stmt_close(st);auth_reply(c,"500 Internal Server Error","{\"error\":\"Could not prepare account creation.\"}");return;}MYSQL_BIND b[4];memset(b,0,sizeof b);unsigned long ul=(unsigned long)strlen(username),nl=(unsigned long)strlen(norm),el=(unsigned long)strlen(email),hl=(unsigned long)strlen(hash);b[0].buffer_type=MYSQL_TYPE_STRING;b[0].buffer=username;b[0].buffer_length=ul;b[0].length=&ul;b[1].buffer_type=MYSQL_TYPE_STRING;b[1].buffer=norm;b[1].buffer_length=nl;b[1].length=&nl;b[2].buffer_type=MYSQL_TYPE_STRING;b[2].buffer=email;b[2].buffer_length=el;b[2].length=&el;b[3].buffer_type=MYSQL_TYPE_STRING;b[3].buffer=hash;b[3].buffer_length=hl;b[3].length=&hl;mysql_stmt_bind_param(st,b);int rc=mysql_stmt_execute(st);unsigned int err=mysql_stmt_errno(st);mysql_stmt_close(st);if(rc){if(err==1062)auth_reply(c,"409 Conflict","{\"error\":\"That username or email already has an account.\"}");else auth_reply(c,"500 Internal Server Error","{\"error\":\"Account could not be created. Check the database schema.\"}");return;}auth_reply(c,"201 Created","{\"message\":\"Account created. You can now sign in.\"}");return;}
 MYSQL_STMT *st=mysql_stmt_init(db);const char *q="SELECT user_id,password_hash,is_active FROM users WHERE username_normalized=? LIMIT 1";if(!st||mysql_stmt_prepare(st,q,(unsigned long)strlen(q))){if(st)mysql_stmt_close(st);auth_reply(c,"500 Internal Server Error","{\"error\":\"Could not prepare sign-in.\"}");return;}MYSQL_BIND in;memset(&in,0,sizeof in);unsigned long nl=(unsigned long)strlen(norm);in.buffer_type=MYSQL_TYPE_STRING;in.buffer=norm;in.buffer_length=nl;in.length=&nl;mysql_stmt_bind_param(st,&in);if(mysql_stmt_execute(st)){mysql_stmt_close(st);auth_reply(c,"500 Internal Server Error","{\"error\":\"Sign-in request failed.\"}");return;}MYSQL_BIND out[3];memset(out,0,sizeof out);unsigned long long uid=0;char stored[256]={0};unsigned long sl=0;unsigned char active=0;out[0].buffer_type=MYSQL_TYPE_LONGLONG;out[0].buffer=&uid;out[0].is_unsigned=1;out[1].buffer_type=MYSQL_TYPE_STRING;out[1].buffer=stored;out[1].buffer_length=sizeof stored-1;out[1].length=&sl;out[2].buffer_type=MYSQL_TYPE_TINY;out[2].buffer=&active;out[2].is_unsigned=1;mysql_stmt_bind_result(st,out);int fetched=mysql_stmt_fetch(st);mysql_stmt_close(st);if(fetched!=0||!active||!check_hash(password,stored)){auth_reply(c,"401 Unauthorized","{\"error\":\"Username or password is incorrect.\"}");return;}unsigned char raw[32],digest[32];if(!secure_random(raw,sizeof raw)||!sha256(raw,sizeof raw,digest)||!hex_encode(raw,sizeof raw,token,sizeof token)||!hex_encode(digest,sizeof digest,token_hash,sizeof token_hash)){auth_reply(c,"500 Internal Server Error","{\"error\":\"Could not start a secure session.\"}");return;}MYSQL_STMT *ss=mysql_stmt_init(db);q="INSERT INTO auth_sessions(user_id,token_hash,expires_at) VALUES(?,?,DATE_ADD(UTC_TIMESTAMP(),INTERVAL 7 DAY))";if(!ss||mysql_stmt_prepare(ss,q,(unsigned long)strlen(q))){if(ss)mysql_stmt_close(ss);auth_reply(c,"500 Internal Server Error","{\"error\":\"Run the updated database schema before signing in.\"}");return;}MYSQL_BIND sb[2];memset(sb,0,sizeof sb);sb[0].buffer_type=MYSQL_TYPE_LONGLONG;sb[0].buffer=&uid;sb[0].is_unsigned=1;unsigned long thl=(unsigned long)strlen(token_hash);sb[1].buffer_type=MYSQL_TYPE_STRING;sb[1].buffer=token_hash;sb[1].buffer_length=thl;sb[1].length=&thl;mysql_stmt_bind_param(ss,sb);int src=mysql_stmt_execute(ss);mysql_stmt_close(ss);if(src){auth_reply(c,"500 Internal Server Error","{\"error\":\"Could not save login session.\"}");return;}snprintf(response,sizeof response,"{\"token\":\"%s\",\"username\":\"%s\",\"expiresIn\":604800}",token,username);auth_reply(c,"200 OK",response);}
static void auth_logout(socket_t c,const char *req){if(!db){auth_reply(c,"503 Service Unavailable","{\"error\":\"Database unavailable.\"}");return;}const char *p=strstr(req,"Authorization: Bearer ");if(!p)p=strstr(req,"authorization: Bearer ");if(!p){auth_reply(c,"401 Unauthorized","{\"error\":\"Sign-in required.\"}");return;}p=strstr(p,"Bearer ")+7;char token[65];size_t i=0;while(p[i]&&p[i]!='\r'&&p[i]!='\n'&&i<sizeof token-1){token[i]=p[i];i++;}token[i]=0;unsigned char raw[32],digest[32];char hashed[65];if(!hex_decode(token,raw,sizeof raw)||!sha256(raw,sizeof raw,digest)||!hex_encode(digest,sizeof digest,hashed,sizeof hashed)){auth_reply(c,"400 Bad Request","{\"error\":\"Invalid session token.\"}");return;}MYSQL_STMT *st=mysql_stmt_init(db);const char *q="DELETE FROM auth_sessions WHERE token_hash=?";if(!st||mysql_stmt_prepare(st,q,(unsigned long)strlen(q))){if(st)mysql_stmt_close(st);auth_reply(c,"500 Internal Server Error","{\"error\":\"Could not end session.\"}");return;}MYSQL_BIND b;memset(&b,0,sizeof b);unsigned long hl=(unsigned long)strlen(hashed);b.buffer_type=MYSQL_TYPE_STRING;b.buffer=hashed;b.buffer_length=hl;b.length=&hl;mysql_stmt_bind_param(st,&b);int rc=mysql_stmt_execute(st);mysql_stmt_close(st);auth_reply(c,rc?"500 Internal Server Error":"200 OK",rc?"{\"error\":\"Could not end session.\"}":"{\"message\":\"Signed out.\"}");}
/* Trip requests are actual persistent jobs. Authorization is resolved from the
 * bearer session; reviewer/admin actions are checked server-side. */
static int session_user(const char *req,unsigned long long *uid,char *role,size_t rolecap){
 if(!db)return 0;
 const char *p=strstr(req,"Authorization: Bearer ");if(!p)p=strstr(req,"authorization: Bearer ");if(!p)return 0;p=strstr(p,"Bearer ")+7;char token[65];size_t i=0;while(p[i]&&p[i]!='\r'&&p[i]!='\n'&&i<64){token[i]=p[i];i++;}token[i]=0;
 unsigned char raw[32],digest[32];char hashed[65],sql[512];if(!hex_decode(token,raw,sizeof raw)||!sha256(raw,sizeof raw,digest)||!hex_encode(digest,sizeof digest,hashed,sizeof hashed))return 0;
 snprintf(sql,sizeof sql,"SELECT u.user_id,u.role FROM auth_sessions s JOIN users u ON u.user_id=s.user_id WHERE s.token_hash='%s' AND s.expires_at>UTC_TIMESTAMP() AND u.is_active=TRUE LIMIT 1",hashed);
 if(mysql_query(db,sql))return 0;MYSQL_RES *res=mysql_store_result(db);MYSQL_ROW row=res?mysql_fetch_row(res):NULL;if(!row){if(res)mysql_free_result(res);return 0;}*uid=strtoull(row[0],NULL,10);snprintf(role,rolecap,"%s",row[1]?row[1]:"user");mysql_free_result(res);return 1;
}
static void admin_session_json(socket_t c,const char *req){unsigned long long uid=0;char role[24];if(!session_user(req,&uid,role,sizeof role)){auth_reply(c,"401 Unauthorized","{\"error\":\"Sign in required.\"}");return;}if(strcmp(role,"admin")){auth_reply(c,"403 Forbidden","{\"error\":\"Owner admin access required.\"}");return;}auth_reply(c,"200 OK","{\"isAdmin\":true}");}
static int body_number(const char *body,const char *key,int fallback){char needle[80];snprintf(needle,sizeof needle,"\"%s\"",key);const char *p=strstr(body,needle);if(!p)return fallback;p=strchr(p,':');if(!p)return fallback;p++;while(*p&&isspace((unsigned char)*p))p++;char *end=NULL;long v=strtol(p,&end,10);if(end==p||v<0||v>30000)return fallback;return (int)v;}
static char *request_body(char *req){char *p=strstr(req,"\r\n\r\n");return p?p+4:NULL;}
static const char *priority_order=" ORDER BY CASE WHEN TIMESTAMPDIFF(SECOND,submitted_at,UTC_TIMESTAMP())>=86400 THEN 0 ELSE 1 END ASC,CASE WHEN TIMESTAMPDIFF(SECOND,submitted_at,UTC_TIMESTAMP())>=86400 THEN submitted_at ELSE NULL END ASC,CASE WHEN TIMESTAMPDIFF(SECOND,submitted_at,UTC_TIMESTAMP())<86400 THEN travel_date ELSE NULL END ASC,submitted_at ASC,request_id ASC";
typedef struct { unsigned long long id; int allocation[3]; int maximum[3]; } BankerProcess;
static int banker_safety_check(const BankerProcess *processes,size_t count,const int initial_work[3],unsigned long long *sequence,size_t *sequence_count);
 static void trip_requests_get(socket_t c,const char *req){unsigned long long uid=0;char role[24];if(!session_user(req,&uid,role,sizeof role)){auth_reply(c,"401 Unauthorized","{\"error\":\"Sign in to view trip requests.\"}");return;}char sql[1400];int staff=OWNER_MODE&&!strcmp(role,"admin");const char *cols="SELECT r.request_id,r.destination,DATE_FORMAT(r.travel_date,'%%Y-%%m-%%d'),r.travellers,r.guide_units,r.vehicle_units,r.status,DATE_FORMAT(r.submitted_at,'%%Y-%%m-%%d %%H:%%i'),u.username,GREATEST(0,TIMESTAMPDIFF(HOUR,r.submitted_at,UTC_TIMESTAMP())) AS waiting_hours,r.decision_note,r.allocated_permits,r.allocated_guides,r.allocated_vehicles,r.resources_released_at IS NULL AND r.travel_date<=CURDATE() AS can_release FROM trip_requests r JOIN users u ON u.user_id=r.user_id WHERE ";snprintf(sql,sizeof sql,"%s%s",cols,staff?"(r.status IN ('PENDING','PROCESSING','WAITING_RESOURCE') OR (r.status='APPROVED' AND r.resources_released_at IS NULL AND r.travel_date<=CURDATE()))":"r.user_id=");if(!staff){snprintf(sql,sizeof sql,"%sr.user_id=%llu",cols,uid);}strncat(sql,priority_order,sizeof sql-strlen(sql)-1);if(mysql_query(db,sql)){json_error(c,"Could not read trip request queue (apply database/schema.sql first)");return;}MYSQL_RES *res=mysql_store_result(db);if(!res){json_error(c,"Could not read request rows");return;}size_t cap=65536,used=0;char *out=malloc(cap);if(!out){mysql_free_result(res);json_error(c,"Not enough memory");return;}out[used++]='[';MYSQL_ROW row;int first=1;while((row=mysql_fetch_row(res))&&used<cap-512){if(!first)out[used++]=',';first=0;used+=(size_t)snprintf(out+used,cap-used,"{\"canDecide\":%s,\"id\":%s,\"destination\":\"",staff?"true":"false",row[0]);json_string(out,cap,&used,row[1]);used+=(size_t)snprintf(out+used,cap-used,"\",\"travelDate\":\"%s\",\"travellers\":%s,\"guides\":%s,\"vehicles\":%s,\"status\":\"%s\",\"submittedAt\":\"%s\",\"username\":\"",row[2],row[3],row[4],row[5],row[6],row[7]);json_string(out,cap,&used,row[8]);used+=(size_t)snprintf(out+used,cap-used,"\",\"waitingHours\":%s,\"decisionNote\":\"",row[9]);json_string(out,cap,&used,row[10]);used+=(size_t)snprintf(out+used,cap-used,"\",\"allocation\":{\"permits\":%s,\"guides\":%s,\"vehicles\":%s},\"need\":{\"permits\":%d,\"guides\":%d,\"vehicles\":%d},\"canRelease\":%s}",row[11]?row[11]:"0",row[12]?row[12]:"0",row[13]?row[13]:"0",atoi(row[3])-atoi(row[11]?row[11]:"0"),atoi(row[4])-atoi(row[12]?row[12]:"0"),atoi(row[5])-atoi(row[13]?row[13]:"0"),row[14]&&!strcmp(row[14],"1")?"true":"false");}out[used++]=']';out[used]=0;mysql_free_result(res);char *wrapped=malloc(cap+64);if(!wrapped){free(out);json_error(c,"Not enough memory");return;}snprintf(wrapped,cap+64,"{\"canDecide\":%s,\"requests\":%s}",staff?"true":"false",out);free(out);send_response(c,"200 OK","application/json; charset=utf-8",wrapped);free(wrapped);}
static void trip_request_submit(socket_t c,const char *req,const char *body){unsigned long long uid=0;char role[24],dest[151],date[16];if(!session_user(req,&uid,role,sizeof role)){auth_reply(c,"401 Unauthorized","{\"error\":\"Sign in before sending a trip request.\"}");return;}if(!json_field(body,"destination",dest,sizeof dest)||!json_field(body,"travelDate",date,sizeof date)||strlen(dest)<2||strlen(date)!=10||date[4]!='-'||date[7]!='-'){auth_reply(c,"400 Bad Request","{\"error\":\"Enter a destination and a valid YYYY-MM-DD travel date.\"}");return;}for(int i=0;i<10;i++)if(i!=4&&i!=7&&!isdigit((unsigned char)date[i])){auth_reply(c,"400 Bad Request","{\"error\":\"Travel date must be YYYY-MM-DD.\"}");return;}int people=body_number(body,"travellers",1),guides=body_number(body,"guides",0),vehicles=body_number(body,"vehicles",0);if(people<1||people>30||guides>10||vehicles>10){auth_reply(c,"400 Bad Request","{\"error\":\"Use 1-30 travellers and no more than 10 guide/vehicle units.\"}");return;}char esc[302],sql[1200];unsigned long en=mysql_real_escape_string(db,esc,dest,(unsigned long)strlen(dest));esc[en]=0;
 if(mysql_query(db,"START TRANSACTION")){json_error(c,"Could not start request transaction");return;}snprintf(sql,sizeof sql,"SELECT user_id FROM users WHERE user_id=%llu FOR UPDATE",uid);if(mysql_query(db,sql)){mysql_query(db,"ROLLBACK");json_error(c,"Could not lock account for pending-request limit");return;}MYSQL_RES *lock=mysql_store_result(db);MYSQL_ROW lrow=lock?mysql_fetch_row(lock):NULL;if(!lrow){if(lock)mysql_free_result(lock);mysql_query(db,"ROLLBACK");auth_reply(c,"401 Unauthorized","{\"error\":\"Account is unavailable.\"}");return;}mysql_free_result(lock);snprintf(sql,sizeof sql,"SELECT COUNT(*) FROM trip_requests WHERE user_id=%llu AND status IN ('PENDING','PROCESSING','WAITING_RESOURCE')",uid);if(mysql_query(db,sql)){mysql_query(db,"ROLLBACK");json_error(c,"Could not count pending requests");return;}MYSQL_RES *cr=mysql_store_result(db);MYSQL_ROW crow=cr?mysql_fetch_row(cr):NULL;int count=crow?atoi(crow[0]):0;if(cr)mysql_free_result(cr);if(count>=3){mysql_query(db,"ROLLBACK");auth_reply(c,"409 Conflict","{\"error\":\"You already have 3 pending trip requests. Wait until one is decided before sending another.\"}");return;}snprintf(sql,sizeof sql,"INSERT INTO trip_requests(user_id,destination,travel_date,travellers,guide_units,vehicle_units) SELECT %llu,'%s',STR_TO_DATE('%s','%%Y-%%m-%%d'),%d,%d,%d WHERE STR_TO_DATE('%s','%%Y-%%m-%%d')>=CURDATE()",uid,esc,date,people,guides,vehicles,date);if(mysql_query(db,sql)){mysql_query(db,"ROLLBACK");json_error(c,"Could not save request");return;}if(mysql_affected_rows(db)!=1){mysql_query(db,"ROLLBACK");auth_reply(c,"400 Bad Request","{\"error\":\"Choose today or a future travel date.\"}");return;}unsigned long long id=mysql_insert_id(db);if(mysql_query(db,"COMMIT")){mysql_query(db,"ROLLBACK");json_error(c,"Could not commit request");return;}char out[256];snprintf(out,sizeof out,"{\"message\":\"Trip request queued for priority review.\",\"id\":%llu,\"pendingLimit\":3}",id);auth_reply(c,"201 Created",out);}
static char *banker_result_json(int safe,const char *status,const char *message,const int work[3],const int grant[3],const BankerProcess *p,size_t n,const unsigned long long *sequence,size_t sequence_count){
 size_t cap=4096+n*256;char *out=(char*)calloc(cap,1);if(!out)return NULL;
 size_t used=(size_t)snprintf(out,cap,"{\"status\":\"%s\",\"bankerSafe\":%s,\"available\":[%d,%d,%d],\"grant\":[%d,%d,%d],\"safeSequence\":[",status,safe?"true":"false",work[0],work[1],work[2],grant[0],grant[1],grant[2]);
 for(size_t i=0;i<sequence_count&&used<cap-64;i++)used+=(size_t)snprintf(out+used,cap-used,"%s%llu",i?",":"",sequence[i]);
 used+=(size_t)snprintf(out+used,cap-used,"],\"processes\":[");
 for(size_t i=0;i<n&&used<cap-240;i++){int need[3];for(int r=0;r<3;r++)need[r]=p[i].maximum[r]-p[i].allocation[r];used+=(size_t)snprintf(out+used,cap-used,"%s{\"id\":%llu,\"allocation\":[%d,%d,%d],\"max\":[%d,%d,%d],\"need\":[%d,%d,%d]}",i?",":"",p[i].id,p[i].allocation[0],p[i].allocation[1],p[i].allocation[2],p[i].maximum[0],p[i].maximum[1],p[i].maximum[2],need[0],need[1],need[2]);}
 snprintf(out+used,cap-used,"],\"message\":\"%s\"}",message);return out;
}
static void trip_request_allocate(socket_t c,const char *req,const char *path,const char *body,int grant_all_remaining){
 unsigned long long uid=0;char role[24];
 if(!session_user(req,&uid,role,sizeof role)){auth_reply(c,"401 Unauthorized","{\"error\":\"Sign in required.\"}");return;}
 if(strcmp(role,"admin")){auth_reply(c,"403 Forbidden","{\"error\":\"Only the site owner can allocate trip resources.\"}");return;}
 const char *idp=strstr(path,"/api/trip-requests/");idp=idp?idp+19:NULL;
 if(!idp||!isdigit((unsigned char)*idp)){auth_reply(c,"400 Bad Request","{\"error\":\"Invalid request id.\"}");return;}
 unsigned long long rid=strtoull(idp,NULL,10);int grant[3]={0,0,0};
 if(!grant_all_remaining){
  if(!body||!strstr(body,"permits")||!strstr(body,"guides")||!strstr(body,"vehicles")){auth_reply(c,"400 Bad Request","{\"error\":\"Enter permit, guide and vehicle grant quantities.\"}");return;}
  grant[0]=body_number(body,"permits",0);grant[1]=body_number(body,"guides",0);grant[2]=body_number(body,"vehicles",0);
  if(grant[0]<0||grant[1]<0||grant[2]<0){auth_reply(c,"400 Bad Request","{\"error\":\"Grant quantities cannot be negative.\"}");return;}
 }
 char sql[1400];snprintf(sql,sizeof sql,"SELECT destination,DATE_FORMAT(travel_date,'%%Y-%%m-%%d'),status FROM trip_requests WHERE request_id=%llu",rid);
 if(mysql_query(db,sql)){json_error(c,"Could not locate trip request");return;}
 MYSQL_RES *lookup=mysql_store_result(db);MYSQL_ROW lr=lookup?mysql_fetch_row(lookup):NULL;
 if(!lr){if(lookup)mysql_free_result(lookup);auth_reply(c,"404 Not Found","{\"error\":\"Trip request was not found.\"}");return;}
 char dest[151],date[16],initial_status[24];snprintf(dest,sizeof dest,"%s",lr[0]);snprintf(date,sizeof date,"%s",lr[1]);snprintf(initial_status,sizeof initial_status,"%s",lr[2]);mysql_free_result(lookup);
 if(strcmp(initial_status,"PROCESSING")&&strcmp(initial_status,"WAITING_RESOURCE")){auth_reply(c,"409 Conflict","{\"error\":\"Start processing this request before allocating resources.\"}");return;}
 char esc[302];unsigned long en=mysql_real_escape_string(db,esc,dest,(unsigned long)strlen(dest));esc[en]=0;
 if(mysql_query(db,"START TRANSACTION")){json_error(c,"Could not begin resource grant transaction");return;}
 snprintf(sql,sizeof sql,"INSERT IGNORE INTO resource_inventory(destination,travel_date) VALUES('%s','%s')",esc,date);
 if(mysql_query(db,sql)){mysql_query(db,"ROLLBACK");json_error(c,"Could not initialize resource pool");return;}
 snprintf(sql,sizeof sql,"SELECT permit_capacity,guide_capacity,vehicle_capacity FROM resource_inventory WHERE destination='%s' AND travel_date='%s' FOR UPDATE",esc,date);
 if(mysql_query(db,sql)){mysql_query(db,"ROLLBACK");json_error(c,"Could not lock resource pool");return;}
 MYSQL_RES *ir=mysql_store_result(db);MYSQL_ROW inv=ir?mysql_fetch_row(ir):NULL;int capacity[3]={inv?atoi(inv[0]):20,inv?atoi(inv[1]):5,inv?atoi(inv[2]):3};if(ir)mysql_free_result(ir);
  snprintf(sql,sizeof sql,"SELECT request_id,travellers,guide_units,vehicle_units,status,allocated_permits,allocated_guides,allocated_vehicles FROM trip_requests WHERE destination='%s' AND travel_date='%s' AND (status IN ('PENDING','PROCESSING','WAITING_RESOURCE') OR (status='APPROVED' AND resources_released_at IS NULL)) ORDER BY request_id FOR UPDATE",esc,date);
 if(mysql_query(db,sql)){mysql_query(db,"ROLLBACK");json_error(c,"Could not lock Banker process state; apply migrate_banker_allocations.sql");return;}
 MYSQL_RES *pr=mysql_store_result(db);if(!pr){mysql_query(db,"ROLLBACK");json_error(c,"Could not read Banker process state");return;}
 size_t count=(size_t)mysql_num_rows(pr);BankerProcess *processes=(BankerProcess*)calloc(count?count:1,sizeof *processes);unsigned long long *sequence=(unsigned long long*)calloc(count?count:1,sizeof *sequence);
 if(!processes||!sequence){free(processes);free(sequence);mysql_free_result(pr);mysql_query(db,"ROLLBACK");json_error(c,"Not enough memory for Banker safety check");return;}
 size_t i=0,candidate=SIZE_MAX;MYSQL_ROW row;int existing_alloc[3]={0,0,0};
 while((row=mysql_fetch_row(pr))&&i<count){processes[i].id=strtoull(row[0],NULL,10);int maxv[3]={atoi(row[1]),atoi(row[2]),atoi(row[3])},alloc[3]={atoi(row[5]),atoi(row[6]),atoi(row[7])};for(int r=0;r<3;r++){processes[i].maximum[r]=maxv[r];processes[i].allocation[r]=alloc[r];existing_alloc[r]+=alloc[r];}if(processes[i].id==rid)candidate=i;i++;}
 mysql_free_result(pr);count=i;
 if(candidate==SIZE_MAX){free(processes);free(sequence);mysql_query(db,"ROLLBACK");auth_reply(c,"409 Conflict","{\"error\":\"Request is no longer active in this resource pool.\"}");return;}
 if(strcmp(initial_status,"PROCESSING")&&strcmp(initial_status,"WAITING_RESOURCE")){free(processes);free(sequence);mysql_query(db,"ROLLBACK");auth_reply(c,"409 Conflict","{\"error\":\"Request changed state; refresh the owner queue.\"}");return;}
 for(int r=0;r<3;r++){int need=processes[candidate].maximum[r]-processes[candidate].allocation[r];if(need<0){free(processes);free(sequence);mysql_query(db,"ROLLBACK");json_error(c,"Stored allocation exceeds this trip's maximum claim");return;}if(grant_all_remaining)grant[r]=need;if(grant[r]>need){free(processes);free(sequence);mysql_query(db,"ROLLBACK");auth_reply(c,"400 Bad Request","{\"error\":\"Grant exceeds this trip's remaining Need.\"}");return;}}
 if(grant[0]==0&&grant[1]==0&&grant[2]==0){free(processes);free(sequence);mysql_query(db,"ROLLBACK");auth_reply(c,"400 Bad Request","{\"error\":\"Enter at least one resource unit to grant.\"}");return;}
 int total_after[3];for(int r=0;r<3;r++){processes[candidate].allocation[r]+=grant[r];total_after[r]=existing_alloc[r]+grant[r];}
 int work[3]={capacity[0]-total_after[0],capacity[1]-total_after[1],capacity[2]-total_after[2]};size_t sequence_count=0;int safe=banker_safety_check(processes,count,work,sequence,&sequence_count);
 if(!safe){char *result=banker_result_json(0,"PROCESSING","Unsafe trial grant: no complete safe sequence. No resources were granted.",work,grant,processes,count,sequence,sequence_count);mysql_query(db,"ROLLBACK");free(processes);free(sequence);if(!result){json_error(c,"Not enough memory to report Banker result");return;}auth_reply(c,"409 Conflict",result);free(result);return;}
 int new_alloc[3];for(int r=0;r<3;r++)new_alloc[r]=processes[candidate].allocation[r];
 int complete=new_alloc[0]==processes[candidate].maximum[0]&&new_alloc[1]==processes[candidate].maximum[1]&&new_alloc[2]==processes[candidate].maximum[2];
 if(complete)snprintf(sql,sizeof sql,"UPDATE trip_requests SET allocated_permits=%d,allocated_guides=%d,allocated_vehicles=%d,status='APPROVED',decided_by=%llu,decided_at=UTC_TIMESTAMP(),decision_note='Banker safe grant completed all resource claims' WHERE request_id=%llu AND status IN ('PROCESSING','WAITING_RESOURCE')",new_alloc[0],new_alloc[1],new_alloc[2],uid,rid);
 else snprintf(sql,sizeof sql,"UPDATE trip_requests SET allocated_permits=%d,allocated_guides=%d,allocated_vehicles=%d,status='PROCESSING',decision_note='Partial resource grant passed Banker safety check' WHERE request_id=%llu AND status IN ('PROCESSING','WAITING_RESOURCE')",new_alloc[0],new_alloc[1],new_alloc[2],rid);
 if(mysql_query(db,sql)||mysql_affected_rows(db)!=1||mysql_query(db,"COMMIT")){mysql_query(db,"ROLLBACK");free(processes);free(sequence);json_error(c,"Could not commit safe resource grant");return;}
 char message[180];snprintf(message,sizeof message,complete?"Safe grant applied; all claims met and trip approved.":"Safe grant applied; trip remains in processing until Need reaches zero.");
 char *result=banker_result_json(1,complete?"APPROVED":"PROCESSING",message,work,grant,processes,count,sequence,sequence_count);free(processes);free(sequence);
 if(!result){json_error(c,"Not enough memory to report Banker result");return;}auth_reply(c,"200 OK",result);free(result);
}static void trip_request_reason_decide(socket_t c,const char *req,const char *path,int unavailable,const char *body){unsigned long long uid=0;char role[24],reason[501]={0},escaped[1002],sql[1800];if(!session_user(req,&uid,role,sizeof role)){auth_reply(c,"401 Unauthorized","{\"error\":\"Sign in required.\"}");return;}if(strcmp(role,"admin")){auth_reply(c,"403 Forbidden","{\"error\":\"Only the site owner can decide trip requests.\"}");return;}const char *idp=strstr(path,"/api/trip-requests/");idp=idp?idp+19:NULL;if(!idp||!isdigit((unsigned char)*idp)){auth_reply(c,"400 Bad Request","{\"error\":\"Invalid request id.\"}");return;}unsigned long long rid=strtoull(idp,NULL,10);if(!body||!json_field(body,"reason",reason,sizeof reason)){auth_reply(c,"400 Bad Request","{\"error\":\"Enter a reason for this decision.\"}");return;}char *a=reason;while(isspace((unsigned char)*a))a++;if(a!=reason)memmove(reason,a,strlen(a)+1);size_t z=strlen(reason);while(z&&isspace((unsigned char)reason[z-1]))reason[--z]=0;if(!z){auth_reply(c,"400 Bad Request","{\"error\":\"The reason cannot be empty.\"}");return;}unsigned long en=mysql_real_escape_string(db,escaped,reason,(unsigned long)z);escaped[en]=0;snprintf(sql,sizeof sql,"SELECT request_id FROM trip_requests WHERE status IN ('PENDING','PROCESSING','WAITING_RESOURCE')%s",priority_order);if(mysql_query(db,sql)){json_error(c,"Could not inspect priority queue");return;}MYSQL_RES *r=mysql_store_result(db);MYSQL_ROW row=r?mysql_fetch_row(r):NULL;unsigned long long top=row?strtoull(row[0],NULL,10):0;if(r)mysql_free_result(r);if(top!=rid){auth_reply(c,"409 Conflict","{\"error\":\"Handle the highest-priority request first.\"}");return;}const char *status=unavailable?"WAITING_RESOURCE":"REJECTED";snprintf(sql,sizeof sql,"UPDATE trip_requests SET status='%s',allocated_permits=0,allocated_guides=0,allocated_vehicles=0,decided_by=%llu,decided_at=UTC_TIMESTAMP(),decision_note='%s' WHERE request_id=%llu AND status IN ('PENDING','PROCESSING','WAITING_RESOURCE')",status,uid,escaped,rid);if(mysql_query(db,sql)||mysql_affected_rows(db)!=1){json_error(c,"Could not save request decision");return;}auth_reply(c,"200 OK",unavailable?"{\"status\":\"WAITING_RESOURCE\",\"message\":\"Resource details saved for the traveler.\"}":"{\"status\":\"REJECTED\",\"message\":\"Rejection reason saved for the traveler.\"}");}
static void trip_request_release(socket_t c,const char *req,const char *path){unsigned long long uid=0;char role[24],sql[700];if(!session_user(req,&uid,role,sizeof role)){auth_reply(c,"401 Unauthorized","{\"error\":\"Sign in required.\"}");return;}if(strcmp(role,"admin")){auth_reply(c,"403 Forbidden","{\"error\":\"Only the site owner can release trip resources.\"}");return;}const char *idp=strstr(path,"/api/trip-requests/");idp=idp?idp+19:NULL;if(!idp||!isdigit((unsigned char)*idp)){auth_reply(c,"400 Bad Request","{\"error\":\"Invalid request id.\"}");return;}unsigned long long rid=strtoull(idp,NULL,10);if(mysql_query(db,"START TRANSACTION")){json_error(c,"Could not begin resource release");return;}snprintf(sql,sizeof sql,"SELECT request_id FROM trip_requests WHERE request_id=%llu AND status='APPROVED' AND travel_date<=CURDATE() AND resources_released_at IS NULL FOR UPDATE",rid);if(mysql_query(db,sql)){mysql_query(db,"ROLLBACK");json_error(c,"Could not lock completed trip");return;}MYSQL_RES *r=mysql_store_result(db);MYSQL_ROW row=r?mysql_fetch_row(r):NULL;if(!row){if(r)mysql_free_result(r);mysql_query(db,"ROLLBACK");auth_reply(c,"409 Conflict","{\"error\":\"Only an approved trip whose travel date has arrived can release its allocation.\"}");return;}if(r)mysql_free_result(r);snprintf(sql,sizeof sql,"UPDATE trip_requests SET allocated_permits=0,allocated_guides=0,allocated_vehicles=0,resources_released_at=UTC_TIMESTAMP(),decision_note='Trip completed; Banker resources released' WHERE request_id=%llu AND status='APPROVED' AND resources_released_at IS NULL",rid);if(mysql_query(db,sql)||mysql_affected_rows(db)!=1||mysql_query(db,"COMMIT")){mysql_query(db,"ROLLBACK");json_error(c,"Could not commit resource release");return;}auth_reply(c,"200 OK","{\"status\":\"APPROVED\",\"message\":\"Trip marked complete. Its allocated resources are now available to the Banker pool.\"}");}
static void json_string(char *out, size_t cap, size_t *used, const char *s) {
    if (*used >= cap) return;
    for (const unsigned char *p=(const unsigned char *)(s?s:""); *p && *used < cap-8; ++p) {
        if (*p=='"' || *p=='\\') out[(*used)++]='\\';
        if (*p=='\n' || *p=='\r') out[(*used)++]=' ';
        else if (*p>=32) out[(*used)++]=(char)*p;
    }
}
static void places_json(socket_t c){
 if(!db){send_response(c,"503 Service Unavailable","application/json; charset=utf-8","{\"error\":\"Database is not connected. Configure MySQL/MariaDB environment variables.\"}");return;}
 const char *q="SELECT p.place_id,p.name,c.name,p.description,p.origin_region,p.difficulty,p.verification_status,p.duration_min_minutes,p.duration_max_minutes,(SELECT r.source_url FROM routes r WHERE r.place_id=p.place_id AND r.source_url IS NOT NULL ORDER BY r.route_id DESC LIMIT 1),(SELECT r.source_note FROM routes r WHERE r.place_id=p.place_id AND r.source_note LIKE 'Submitted by community%' ORDER BY r.route_id DESC LIMIT 1) FROM places p JOIN categories c ON c.category_id=p.category_id WHERE p.verification_status<>'rejected' ORDER BY c.name,p.name LIMIT 1000";
 if(mysql_query(db,q)){json_error(c,"Place query failed");return;} MYSQL_RES *r=mysql_store_result(db);if(!r){json_error(c,"Could not read place results");return;}
 size_t cap=1200000,used=0;char *out=(char*)malloc(cap);if(!out){mysql_free_result(r);json_error(c,"Not enough memory");return;}out[used++]='[';MYSQL_ROW row;int first=1;
 while((row=mysql_fetch_row(r))&&used<cap-1800){if(!first)out[used++]=',';first=0;used+=(size_t)snprintf(out+used,cap-used,"{\"id\":%s,\"name\":\"",row[0]?row[0]:"0");json_string(out,cap,&used,row[1]);used+=(size_t)snprintf(out+used,cap-used,"\",\"category\":\"");json_string(out,cap,&used,row[2]);used+=(size_t)snprintf(out+used,cap-used,"\",\"description\":\"");json_string(out,cap,&used,row[3]);used+=(size_t)snprintf(out+used,cap-used,"\",\"origin\":\"");json_string(out,cap,&used,row[4]);used+=(size_t)snprintf(out+used,cap-used,"\",\"difficulty\":\"");json_string(out,cap,&used,row[5]);used+=(size_t)snprintf(out+used,cap-used,"\",\"verificationStatus\":\"");json_string(out,cap,&used,row[6]);used+=(size_t)snprintf(out+used,cap-used,"\",\"verified\":%s,\"duration\":\"",row[6]&&!strcmp(row[6],"verified")?"true":"false");if(row[7]&&row[8])used+=(size_t)snprintf(out+used,cap-used,"%s–%s minutes",row[7],row[8]);else json_string(out,cap,&used,"Check locally");used+=(size_t)snprintf(out+used,cap-used,"\",\"cost\":null,\"costStatus\":\"Unavailable\",\"costSource\":\"No current price verified\",\"maps\":\"");json_string(out,cap,&used,row[9]?row[9]:row[1]);used+=(size_t)snprintf(out+used,cap-used,"\",\"addedByUser\":%s}",row[10]?"true":"false");}
 out[used++]=']';out[used]=0;mysql_free_result(r);send_response(c,"200 OK","application/json; charset=utf-8",out);free(out);
}
static void trip_request_start(socket_t c,const char *req,const char *path){unsigned long long uid=0;char role[24];if(!session_user(req,&uid,role,sizeof role)){auth_reply(c,"401 Unauthorized","{\"error\":\"Sign in required.\"}");return;}if(strcmp(role,"admin")){auth_reply(c,"403 Forbidden","{\"error\":\"Only the site owner can process requests.\"}");return;}const char *idp=strstr(path,"/api/trip-requests/");idp=idp?idp+19:NULL;if(!idp||!isdigit((unsigned char)*idp)){auth_reply(c,"400 Bad Request","{\"error\":\"Invalid request id.\"}");return;}unsigned long long rid=strtoull(idp,NULL,10);char sql[1200];snprintf(sql,sizeof sql,"SELECT request_id FROM trip_requests WHERE status='PENDING'%s",priority_order);if(mysql_query(db,sql)){json_error(c,"Could not inspect priority queue");return;}MYSQL_RES *r=mysql_store_result(db);MYSQL_ROW row=r?mysql_fetch_row(r):NULL;unsigned long long next=row?strtoull(row[0],NULL,10):0;if(r)mysql_free_result(r);if(next!=rid){auth_reply(c,"409 Conflict","{\"error\":\"Handle the highest-priority request first. Refresh the queue.\"}");return;}snprintf(sql,sizeof sql,"UPDATE trip_requests SET status='PROCESSING' WHERE request_id=%llu AND status='PENDING'",rid);if(mysql_query(db,sql)||mysql_affected_rows(db)!=1){auth_reply(c,"409 Conflict","{\"error\":\"Request is no longer pending.\"}");return;}auth_reply(c,"200 OK","{\"status\":\"PROCESSING\",\"message\":\"Request entered PROCESSING state in priority order.\"}");}
static int banker_safety_check(const BankerProcess *processes,size_t count,const int initial_work[3],unsigned long long *sequence,size_t *sequence_count){int work[3]={initial_work[0],initial_work[1],initial_work[2]};unsigned char *finished=(unsigned char*)calloc(count?count:1,1);if(sequence_count)*sequence_count=0;if(work[0]<0||work[1]<0||work[2]<0||!finished){free(finished);return 0;}size_t completed=0;while(completed<count){int progressed=0;for(size_t i=0;i<count;i++){if(finished[i])continue;int can_finish=1;for(int r=0;r<3;r++){int need=processes[i].maximum[r]-processes[i].allocation[r];if(need<0||need>work[r]){can_finish=0;break;}}if(!can_finish)continue;for(int r=0;r<3;r++)work[r]+=processes[i].allocation[r];finished[i]=1;if(sequence)sequence[completed]=processes[i].id;completed++;progressed=1;}if(!progressed)break;}if(sequence_count)*sequence_count=completed;free(finished);return completed==count;}
static const char *mime(const char *p){const char *e=strrchr(p,'.');if(!e)return "text/plain";if(!strcmp(e,".html"))return "text/html; charset=utf-8";if(!strcmp(e,".css"))return "text/css; charset=utf-8";if(!strcmp(e,".js"))return "application/javascript; charset=utf-8";if(!strcmp(e,".png"))return "image/png";return "application/octet-stream";}
static void static_file(socket_t c,const char *path){char file[1024];const char *rel=path;if(!strcmp(path,"/"))rel="/index.html";if(strstr(rel,"..")||strchr(rel,'\\')){send_response(c,"400 Bad Request","text/plain","Bad path");return;}snprintf(file,sizeof file,"%s%s",ROOT,rel);FILE *f=fopen(file,"rb");if(!f){send_response(c,"404 Not Found","text/plain","Not found");return;}fseek(f,0,SEEK_END);long n=ftell(f);rewind(f);if(n<0||n>12000000){fclose(f);send_response(c,"413 Content Too Large","text/plain","File too large");return;}char *b=(char*)malloc((size_t)n+1);if(!b){fclose(f);send_response(c,"500 Internal Server Error","text/plain","Memory error");return;}size_t got=fread(b,1,(size_t)n,f);fclose(f);char h[512];int hn=snprintf(h,sizeof h,"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %zu\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n",mime(file),got);send(c,h,hn,0);send(c,b,(int)got,0);free(b);}
static void queue_lock_enter(void){
#ifdef _WIN32
    EnterCriticalSection(&request_lock);
#else
    pthread_mutex_lock(&request_lock);
#endif
}
static void queue_lock_leave(void){
#ifdef _WIN32
    LeaveCriticalSection(&request_lock);
#else
    pthread_mutex_unlock(&request_lock);
#endif
}
static void queue_wait_ready(void){
#ifdef _WIN32
    SleepConditionVariableCS(&request_ready,&request_lock,INFINITE);
#else
    pthread_cond_wait(&request_ready,&request_lock);
#endif
}
static void queue_wait_space(void){
#ifdef _WIN32
    SleepConditionVariableCS(&queue_space,&request_lock,INFINITE);
#else
    pthread_cond_wait(&queue_space,&request_lock);
#endif
}
static void queue_signal_ready(void){
#ifdef _WIN32
    WakeConditionVariable(&request_ready);
#else
    pthread_cond_signal(&request_ready);
#endif
}
static void queue_signal_space(void){
#ifdef _WIN32
    WakeConditionVariable(&queue_space);
#else
    pthread_cond_signal(&queue_space);
#endif
}
static void worker_database_init(void){
    if(mysql_thread_init()!=0){fprintf(stderr,"Worker could not initialize MySQL thread state.\n");return;}
    MYSQL *conn=mysql_init(NULL);if(!conn){fprintf(stderr,"Worker mysql_init failed.\n");return;}
    const char *host=getenv("MYSQL_HOST"),*user=getenv("MYSQL_USER"),*pass=getenv("MYSQL_PASSWORD"),*name=getenv("MYSQL_DATABASE");
    if(mysql_real_connect(conn,host?host:"127.0.0.1",user?user:"offtrail_app",pass?pass:"",name?name:"offtrail",3306,NULL,0)){db=conn;fprintf(stdout,"Worker database connection ready.\n");}
    else {fprintf(stderr,"Worker database unavailable: %s\n",mysql_error(conn));mysql_close(conn);}
}
static int queue_take(int slot,socket_t *client){
    queue_lock_enter();while(request_count==0)queue_wait_ready();*client=request_queue[request_head];request_head=(request_head+1)%REQUEST_QUEUE_CAP;request_count--;active_workers++;worker_busy[slot]=1;queue_signal_space();queue_lock_leave();return 1;
}
static void queue_finish(int slot){queue_lock_enter();if(active_workers>0)active_workers--;worker_busy[slot]=0;requests_completed++;queue_lock_leave();}
#ifdef _WIN32
static DWORD WINAPI request_worker(LPVOID arg){int slot=(int)(intptr_t)arg;worker_database_init();for(;;){socket_t c;queue_take(slot,&c);handle(c);CLOSESOCK(c);queue_finish(slot);}}
#else
static void *request_worker(void *arg){int slot=(int)(intptr_t)arg;worker_database_init();for(;;){socket_t c;queue_take(slot,&c);handle(c);CLOSESOCK(c);queue_finish(slot);}return NULL;}
#endif
static int queue_submit(socket_t client){queue_lock_enter();while(request_count==REQUEST_QUEUE_CAP)queue_wait_space();request_queue[request_tail]=client;request_tail=(request_tail+1)%REQUEST_QUEUE_CAP;request_count++;requests_accepted++;queue_signal_ready();queue_lock_leave();return 1;}
static void runtime_json(socket_t c){char body[1400];unsigned long long pid;
#ifdef _WIN32
    pid=(unsigned long long)GetCurrentProcessId();
#else
    pid=(unsigned long long)getpid();
#endif
    queue_lock_enter();int queued=request_count,active=active_workers;unsigned long long accepted=requests_accepted,completed=requests_completed;int states[WORKER_COUNT];for(int i=0;i<WORKER_COUNT;i++)states[i]=worker_busy[i];queue_lock_leave();
    int n=snprintf(body,sizeof body,"{\"processId\":%llu,\"workerCount\":%d,\"queueCapacity\":%d,\"queuedRequests\":%d,\"activeWorkers\":%d,\"acceptedRequests\":%llu,\"completedRequests\":%llu,\"dispatch\":\"FCFS bounded request queue\",\"workers\":[",pid,WORKER_COUNT,REQUEST_QUEUE_CAP,queued,active,accepted,completed);
    for(int i=0;i<WORKER_COUNT;i++)n+=snprintf(body+n,sizeof body-(size_t)n,"%s{\"id\":\"W%d\",\"state\":\"%s\"}",i?",":"",i+1,states[i]?"processing":"waiting");snprintf(body+n,sizeof body-(size_t)n,"]}");send_response(c,"200 OK","application/json; charset=utf-8",body);
}
#include "user_content_impl.h"
static void handle(socket_t c){static THREAD_LOCAL char req[REQ_CAP+1];int n=receive_http_request(c,req);if(n<=0)return;char method[12]={0},path[512]={0};sscanf(req,"%11s %511s",method,path);if(OWNER_MODE){int api_ok=(!strcmp(method,"GET")&&!strcmp(path,"/api/admin/session"))||(!strcmp(method,"GET")&&!strcmp(path,"/api/trip-requests"))||(!strcmp(method,"POST")&&!strncmp(path,"/api/trip-requests/",18))||(!strcmp(method,"GET")&&!strcmp(path,"/api/submissions"))||(!strcmp(method,"POST")&&!strncmp(path,"/api/submissions/",17))||(!strcmp(method,"GET")&&!strncmp(path,"/api/submission-photos/",23))||(!strcmp(method,"POST")&&(!strcmp(path,"/api/auth/login")||!strcmp(path,"/api/auth/logout")));int static_ok=!strcmp(method,"GET")&&(!strcmp(path,"/admin")||!strcmp(path,"/admin/")||!strcmp(path,"/admin.html")||!strcmp(path,"/admin.js")||!strcmp(path,"/styles.css")||!strncmp(path,"/assets/",8));if(!api_ok&&!static_ok){send_response(c,"404 Not Found","application/json","{\"error\":\"Route not found on owner service.\"}");return;}}else if(!strcmp(path,"/admin")||!strcmp(path,"/admin/")||!strcmp(path,"/admin.html")||!strcmp(path,"/admin.js")||!strcmp(path,"/api/submissions")&&(!strcmp(method,"GET"))||!strncmp(path,"/api/submissions/",17)||!strncmp(path,"/api/trip-requests/",18)&&(!strstr(path,"/" )||strstr(path,"/start")||strstr(path,"/approve")||strstr(path,"/reject"))){if(!strcmp(path,"/api/admin/session")){admin_session_json(c,req);return;}auth_reply(c,"403 Forbidden","{\"error\":\"Use the owner service at http://localhost:5001 for review queues.\"}");return;}if(!strcmp(method,"OPTIONS")){send_response(c,"204 No Content","text/plain","");return;}if(!strcmp(method,"GET")&&!strcmp(path,"/api/admin/session")){admin_session_json(c,req);return;}if(!strcmp(method,"GET")&&(!strcmp(path,"/admin")||!strcmp(path,"/admin/"))){static_file(c,"/admin.html");return;}if(!strcmp(method,"GET")&&!strcmp(path,"/api/os/runtime")){runtime_json(c);return;}if(!strcmp(method,"GET")&&!strncmp(path,"/api/os/",8)){char body[32000];if(os_lab_response(path,body,sizeof body))send_response(c,"200 OK","application/json; charset=utf-8",body);else send_response(c,"404 Not Found","application/json","{\"error\":\"Unknown OS Lab simulation.\"}");return;}if(!strcmp(path,"/api/health")){send_response(c,"200 OK","application/json",db?"{\"status\":\"ok\",\"database\":\"connected\",\"backend\":\"C\"}":"{\"status\":\"degraded\",\"database\":\"disconnected\",\"backend\":\"C\"}");return;}if(!strcmp(path,"/api/places")){places_json(c);return;}if(!strcmp(path,"/api/visits")&&!strcmp(method,"GET")){uc_visits_get(c,req);return;}if(!strcmp(path,"/api/visits")&&!strcmp(method,"POST")){char *body=request_body(req);if(!body){auth_reply(c,"400 Bad Request","{\"error\":\"Invalid request body.\"}");return;}uc_visit_save(c,req,body);return;}if(!strcmp(path,"/api/submissions")&&!strcmp(method,"GET")){uc_submissions_get(c,req);return;}if(!strcmp(path,"/api/submissions")&&!strcmp(method,"POST")){char *body=request_body(req);if(!body){auth_reply(c,"400 Bad Request","{\"error\":\"Invalid request body.\"}");return;}uc_submission_create(c,req,body);return;}if(!strncmp(path,"/api/visit-photos/",18)&&!strcmp(method,"GET")){uc_photo_endpoint(c,req,path,0);return;}if(!strncmp(path,"/api/submission-photos/",23)&&!strcmp(method,"GET")){uc_photo_endpoint(c,req,path,1);return;}if(!strncmp(path,"/api/submissions/",17)&&!strcmp(method,"POST")){if(strstr(path,"/approve"))uc_submission_decide(c,req,path,1);else if(strstr(path,"/reject"))uc_submission_decide(c,req,path,0);else auth_reply(c,"404 Not Found","{\"error\":\"Unknown review action.\"}");return;}if(!strcmp(path,"/api/trip-requests")&&!strcmp(method,"GET")){trip_requests_get(c,req);return;}if(!strcmp(path,"/api/trip-requests")&&!strcmp(method,"POST")){char *body=request_body(req);if(!body){auth_reply(c,"400 Bad Request","{\"error\":\"Invalid request body.\"}");return;}trip_request_submit(c,req,body);return;}if(!strncmp(path,"/api/trip-requests/",18)&&!strcmp(method,"POST")){if(strstr(path,"/start"))trip_request_start(c,req,path);else if(strstr(path,"/allocate"))trip_request_allocate(c,req,path,request_body(req),0);else if(strstr(path,"/approve"))trip_request_allocate(c,req,path,NULL,1);else if(strstr(path,"/unavailable"))trip_request_reason_decide(c,req,path,1,request_body(req));else if(strstr(path,"/reject"))trip_request_reason_decide(c,req,path,0,request_body(req));else if(strstr(path,"/release"))trip_request_release(c,req,path);else auth_reply(c,"404 Not Found","{\"error\":\"Unknown trip request action.\"}");return;}if(!strcmp(path,"/api/auth/logout")&&!strcmp(method,"POST")){auth_logout(c,req);return;}if(!strncmp(path,"/api/auth/",10)&&!strcmp(method,"POST")){char *body=request_body(req);if(!body){auth_reply(c,"400 Bad Request","{\"error\":\"Invalid request body.\"}");return;}auth_post(c,path,body);return;}if(!strcmp(method,"GET")){static_file(c,path);return;}send_response(c,"404 Not Found","application/json","{\"error\":\"Route not found\"}");}
static int receive_http_request(socket_t c,char *req){int n=0;while(n<REQ_CAP){int got=recv(c,req+n,REQ_CAP-n,0);if(got<=0)return n;n+=got;req[n]=0;char *sep=strstr(req,"\r\n\r\n");if(!sep)continue;size_t header=(size_t)(sep+4-req);char *cl=strstr(req,"Content-Length:");if(!cl)cl=strstr(req,"content-length:");if(!cl)break;long body=strtol(strchr(cl,':')+1,NULL,10);if(body<0||body>REQ_CAP)break;if((size_t)n>=header+(size_t)body)break;}req[n]=0;return n;}
int main(int argc,char **argv){
    if(argc>1&&!strcmp(argv[1],"--owner")){OWNER_MODE=1;SERVER_PORT=5001;}else if(argc>1){fprintf(stderr,"Usage: offtrail_server.exe [--owner]\n");return 1;}
    mysql_library_init(0,NULL,NULL);
#ifdef _WIN32
    WSADATA w;if(WSAStartup(MAKEWORD(2,2),&w)!=0){fprintf(stderr,"Winsock startup failed\n");return 1;}InitializeCriticalSection(&request_lock);InitializeConditionVariable(&request_ready);InitializeConditionVariable(&queue_space);
    HANDLE workers[WORKER_COUNT];for(int i=0;i<WORKER_COUNT;i++){workers[i]=CreateThread(NULL,0,request_worker,(LPVOID)(intptr_t)i,0,NULL);if(!workers[i]){fprintf(stderr,"Could not start request worker %d\n",i+1);return 2;}}
#else
    pthread_t workers[WORKER_COUNT];for(int i=0;i<WORKER_COUNT;i++)if(pthread_create(&workers[i],NULL,request_worker,(void*)(intptr_t)i)!=0){fprintf(stderr,"Could not start request worker %d\n",i+1);return 2;}
#endif
    socket_t s=socket(AF_INET,SOCK_STREAM,0);if(s==INVALID_SOCKET){fprintf(stderr,"Socket creation failed\n");return 2;}int yes=1;
#ifdef _WIN32
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(const char*)&yes,sizeof yes);
#else
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);
#endif
    struct sockaddr_in a;memset(&a,0,sizeof a);a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(OWNER_MODE?INADDR_LOOPBACK:INADDR_ANY);a.sin_port=htons(SERVER_PORT);if(bind(s,(struct sockaddr*)&a,sizeof a)==SOCKET_ERROR||listen(s,16)==SOCKET_ERROR){fprintf(stderr,"Could not bind port %d\n",SERVER_PORT);return 3;}printf("OFFTRAIL C server at http://localhost:%d\n",SERVER_PORT);printf("OS request manager: this server process, %d worker threads, FCFS queue capacity %d.\n",WORKER_COUNT,REQUEST_QUEUE_CAP);for(;;){socket_t c=accept(s,NULL,NULL);if(c==INVALID_SOCKET)continue;queue_submit(c);}return 0;
}
