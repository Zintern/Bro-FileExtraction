##! Hash all files with MD5, SHA1 and SHA256
##! Credits to hosom/file-extraction

@load base/files/hash

##! Will be used for the Intel HASH matching.
event file_new(f:file)
        {
        Files::add_analyzer(f, Files::ANALYZER_MD5);
        Files::add_analyzer(f, Files::ANALYZER_SHA1);
        Files::add_analyzer(f, Files::ANALYZER_SHA256);
        }
