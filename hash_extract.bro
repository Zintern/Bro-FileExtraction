
@load base/frameworks/intel
@load base/files/extract
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

##Redefine to path desired.
global path = "/home/zintern/EXTRACTED/temp/";

##Redefine to desired IoC .dat file
redef Intel::read_files += {fmt("%s/otx.dat", @DIR)};

## When a new file is seen:
event file_new(f: fa_file)
{
        Files::add_analyzer(f, Files::ANALYZER_MD5);
        Files::add_analyzer(f, Files::ANALYZER_SHA1);
        Files::add_analyzer(f, Files::ANALYZER_SHA256);
        ##print("FILE HASHED");
        
        ##TEST if normal extraction works:
        local fname = fmt("%s%s-%s", path, f$source, f$id);
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT,[$extract_filename = fname]);
 
 
}

## When a file_hash has been seen
event file_hash(f: fa_file, kind: string, hash: string)
        {
        local seen = Intel::Seen($indicator=hash,
                                 $indicator_type=Intel::FILE_HASH,
                                 $f=f,
                                 $where=Files::IN_HASH);
        ##print(hash);
        
        ##TEST if extraction during the event file_hash works:
        local fname = fmt("%s%s-%s", path, f$source, f$id);
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT,[$extract_filename = fname]);
 
        Intel::seen(seen);
        }
 
## When a match has been found between the seen traffic and the otx.dat file indicators.
event Intel::match(s: Intel::Seen, items:set[Intel::Item])
{
                print("event triggered");
                if(s$indicator_type == Intel::FILE_HASH)
                {
                print("IF SUCCESS");
                print(path);
                print(s$indicator_type);
                
                ## This is usecase 1 extraction: 
                local fname = fmt("%s%s-%s", path, s$f$source, s$f$id);
                print(fname);
                local Files::file: fa_file = s$f;
                Files::add_analyzer(s$f, Files::ANALYZER_EXTRACT,[$extract_filename = fname]);
                }
 
}
