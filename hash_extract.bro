
@load base/frameworks/intel
@load base/files/extract/main
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice
@load base/files/hash
 
global path = "/home/bart/EXTRACTED/temp/";
 
redef Intel::read_files += {fmt("%s/otx.dat", @DIR)};
 
event file_new(f: fa_file)
{
        Files::add_analyzer(f, Files::ANALYZER_MD5);
        Files::add_analyzer(f, Files::ANALYZER_SHA1);
        Files::add_analyzer(f, Files::ANALYZER_SHA256);
       ## print("FILE HASHED");
       ## local fname = fmt("%s%s-%s", path, f$source, f$id);
       ## Files::add_analyzer(f, Files::ANALYZER_EXTRACT,[$extract_filename = fname]);
 
}
 
event file_sniff(f: fa_file, meta: fa_metadata){
 
 
        local hash: string = "f1e977306460d6aacf1676b2e2a8962187a01d2b9a687a0a1178748c3e96f2c4";
        Files::add_analyzer(f, Files::ANALYZER_SHA256);
        local seen = Intel::Seen($indicator= hash,
                                 $indicator_type=Intel::FILE_HASH,
                                 $f=f,
                                 $where=Files::IN_HASH);
        Intel::seen(seen);
 
        ##local fname = fmt("%s%s-%s", path, f$source, f$id);
        ##Files::add_analyzer(f, Files::ANALYZER_EXTRACT,[$extract_filename = fname]);
}
 
 
event file_hash(f: fa_file, kind: string, hash: string)
        {
        if(kind == SHA256){
        f$info$sha256 = hash;
        }
        ##if(kind == sha1){
        ##f$info$sha1 = hash;
        ##}
        ##if(kind == md5){
        ##f$info$md5 = hash;
        ##}
        ##local seen = Intel::Seen($indicator=hash,
        ##                         $indicator_type=Intel::FILE_HASH,
        ##                         $f=f,
        ##                         $where=Files::IN_HASH);
 
        ## print(hash);
        ##local fname = fmt("%s%s-%s", path, f$source, f$id);
        ##Files::add_analyzer(f, Files::ANALYZER_EXTRACT,[$extract_filename = fname]);
 
       ## Intel::seen(seen);
        }
 
event Intel::match(s: Intel::Seen, items:set[Intel::Item])
{
                print("event triggered");
                if(s$indicator_type == Intel::FILE_HASH)
                {
                print("IF SUCCESS");
                print(path);
                print(s$indicator_type);
                local fname = fmt("%s%s-%s", path, s$f$source, s$f$id);
                print(fname);
                ##local Files::file: fa_file = s$f;
                Files::add_analyzer(s$f, Files::ANALYZER_EXTRACT,[$extract_filename = fname]);
                }
 
}
