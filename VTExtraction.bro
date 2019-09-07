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
 
                                        local tmp = split_string(res$body,/\}\},/);
 
                                        if (|tmp| != 0)
                                        {
                                                local stuff = split_string(tmp[1],/\,/);
                                                ## Splitting the string for the postive hits
                                                local positive = split_string(stuff[9],/\:/);
                                                ## Converting the string from pos into integer
                                                local trigger = to_int(pos[1]);
                                                ## Trigger if the value exceeds the VTthreshold
                                                if(trigger >= VTthreshold)
                                                {
                                                        local fname = fmt("VirusTotalEX-%s%s-%s", path, f$source, f$id);
                                                        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
                                                }
                                        }
                                }
                        }
                }
        }
}
