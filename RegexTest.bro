@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

const VTurl = "https://www.virustotal.com/vtapi/v2/file/report" &redef;
const VTapikey = "15b84334813c07faf0241eaa6127aa1afbe0ae22e1e625fb8e44f8c6e0c04bd1" &redef;
const VTthreshold = 2 &redef;

const path: string = "/nsm/bro/extracted/VT_Extraction" &redef;

event file_hash(f: fa_file, kind:string, hash: string)
{
        ## Check file F against the virustotal database
        if (f?$source)
        {
                local data = fmt("resource=%s", hash);
                local key = fmt("-d apikey=%s", VTapikey);

                ## HTTP request to Virustotal via API
                local req: ActiveHTTP::Request = ActiveHTTP::Request($url=VTurl,$method="POST", $client_data=data, $addl_curl_args=key);


                when(local res = ActiveHTTP::request(req))
                {
                        if(|res|>0)
                        {
                                if(res?$body)
                                {
                                        local body = res$body;
                                        local valueA = find_all(body, /positives\"\:\s(\d+)/);

                                        print (valueA);
                                        local t = string_cat(res$body);
                                        ##local tmp: string_array = split_string(body,"/positives\"\:\s(\d+)/");
                                        ##print (t);
                                        local B: string = t;
                                        ##print (B);
                                        local valueB = find_all(B,/\d+/);
                                        ##print (valueB);
                                        ##local tmp = split_string(t,/\}\},/);
                                        ##print(tmp);
                                        ##if ( |tmp| == 1 )
                                        ##{
                                                #local stuff = split_string(tmp[1], /\,/ );
                                                # splitting the string that contains the amount of positive anti-virus hits on ":" "positives:2$
                                                #local pos = split_string(stuff[9],/\:/);
                                                # converting the string from variable pos into a integer
                                                #local notic = to_int(pos[1]);
                                                #print(notic);

                                                ##t = "Test ";
                                                ##body = "Test ";
                                        #}
                                        ##if(|tmp|>1)
                                        ##{
                                        ##      print (tmp);
                                        ##}
                                }
                        }
                }
        }
}
