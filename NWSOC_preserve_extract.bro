@load base/frameworks/intel
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice
@load ./file_extension
 
module PreserveExtract;
 
export  {
        ## Location where files are preserved
        const new_location_file = "./preserved_files/" &redef;
        }
 
## Read intel IoC .dat file, can read multiple feeds
redef Intel::read_files += {fmt("%s/otx.dat", @DIR)};
 
## A new file is seen - event -
event file_new(f: fa_file)
{
        # Hash the files in md5, sha1 and sha256:
        Files::add_analyzer(f, Files::ANALYZER_MD5);
        Files::add_analyzer(f, Files::ANALYZER_SHA1);
        Files::add_analyzer(f, Files::ANALYZER_SHA256);
}
 
## More information is available for file - event -
event file_sniff(f: fa_file, meta: fa_metadata)
{
        local ext = "";
 
        # If MIME is in the pre-defined map:
        local MIME = meta$mime_type;
        if(MIME in mime_to_ext){ext = mime_to_ext[MIME];}
        # If MIME is not in the pre-defined map:
        else {ext = split_string(meta$mime_type, /\//)[1];}
 
        #Extract the file:
        local fname = fmt("%s-%s.%s", f$source, f$id, ext);
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
 
}
 
## A file has been hashed - event -
event file_hash(f: fa_file, kind: string, hash: string)
{
        # Send the new hash to the Intel Framework to find a match:
 
        local seen_hash = Intel::Seen($indicator=hash,
                                 $indicator_type=Intel::FILE_HASH,
                                 $f=f,
                                 $where=Files::IN_HASH);
        Intel::seen(seen_hash);
 
 
}
 
## A file has been seen over a new connection - event -
event file_over_new_connection(f: fa_file, c:connection, is_orig:bool)
{
 
        # If orig is File Originator - IP compare -
        if(is_orig == T){
        local orig:string = cat(c$id$orig_h);
        local seen_orig = Intel::Seen($indicator=orig,
                                        $indicator_type=Intel::ADDR,
                                        $f=f,
                                        $where=Conn::IN_ORIG);
        Intel::seen(seen_orig);
        }
 
        # If resp is File Originator - IP compare -
        if(is_orig == F){
        local resp:string = cat(c$id$resp_h);
        local seen_resp = Intel::Seen($indicator=resp,
                                        $indicator_type=Intel::ADDR,
                                        $f=f,
                                        $where=Conn::IN_RESP);
        Intel::seen(seen_resp);
        }
 
        # If a file originates from a HTTP domain - Domain compare -
        if(f$source == "HTTP" && is_orig == F){
        local domain = (c?$http && c$http?$host) ? c$http$host : "--";
 
        local seen_domain = Intel::Seen($indicator=domain,
                                        $indicator_type=Intel::DOMAIN,
                                        $f=f,
                                        $where=HTTP::IN_HOST_HEADER);
        Intel::seen(seen_domain);
        }
}
 
## A match with the Intel IoC .dat file has been found - event -
event Intel::match(s: Intel::Seen, items:set[Intel::Item])
{
        # If the file info has matched:
        if(s?$f && s$f?$info && s$f$info?$extracted)
        {
                # Get file name
                        local ex_file = s$f$info$extracted;
                # Get path to file
                        local ex_path = cat(FileExtract::prefix, ex_file);
                # Set new path for file
                        local pre_path = cat(new_location_file, ex_file);
 
                # Move files using mv from ex_path to pre_path
                        local ret = system(fmt("mv \"%s\" \"%s\"",
                                str_shell_escape(ex_path),
                                str_shell_escape(pre_path)));
        }
}
