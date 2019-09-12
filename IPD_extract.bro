@load base/frameworks/intel
@load base/files/extract
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice
@load base/frameworks/files
 
module FileExtraction;
 
export {const path: string = "/home/zintern/EXTRACTED" &redef;}
 
redef Intel::read_files += {fmt("%s/otx.dat", @DIR)};
 
event file_new(f: fa_file)
{
        Files::add_analyzer(f, Files::ANALYZER_MD5);
        Files::add_analyzer(f, Files::ANALYZER_SHA1);
        Files::add_analyzer(f, Files::ANALYZER_SHA256);
        print("FILE HASHED");
 
        ## General Source
        local seen1 = Intel::Seen($indicator=f$source,
                                 $indicator_type=Intel::ADDR,
                                 $f=f,
                                 $where=Intel::IN_ANYWHERE);
        print(f$source);
        ##print(f$info$tx_hosts);
        ##print(f$info$rx_hosts);
        Files::add_analyzer(seen1$f, Files::ANALYZER_EXTRACT);
        Intel::seen(seen1);
 
        ## HTTP GET Method - TX Host
        local TX_host =cat(f$info$tx_hosts);
        print(TX_host);
 
        ##local seen2 = Intel::Seen($indicator=TX_host,
        ##                          $indicator_type=Intel::ADDR,
        ##                          $f=f,
        ##                          $where=Intel::IN_ANYWHERE);
        ##Intel::seen(seen2);
 
        ## HTTP POST Method - RX Host
        ##local seen3 = Intel::Seen($indicator=f$info$rx_hosts,
        ##                          $indicator_type=Intel::ADDR,
        ##                          $f=f,
        ##                          $where=Intel::IN_ANYWHERE);
        ##Intel::seen(seen3);
 
 
 
}
 
event Intel::match(s: Intel::Seen, items:set[Intel::Item])
{
                print("event triggered");
                if(s$indicator_type == Intel::ADDR || s$indicator_type == Intel::DOMAIN)
                {
                print("IF SUCCESS");
                print(path);
                print(s$indicator_type);
                local fname = fmt("%s%s-%s", path, s$f$source, s$f$id);
                print(fname);
                ##local file: fa_file = s$f;
                Files::add_analyzer(s$f, Files::ANALYZER_EXTRACT,[$extract_filename = fname]);
                }
 
}
