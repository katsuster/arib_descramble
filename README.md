# arib_descramble

This is simple descrambler based on ARIB STD-B25 standard.

* Input from DVB API frontend device such as /dev/dvb/adapter0/dvr0 or any MPEG2-TS files
* Decrypt MULTI2
* Send MPEG2-TS to other host using UDP

# How to use

Please setup the devices before using this tool.

* Tuner: Tune the DVB API frontend device using tools as you like
  * If you don't have any DVB API tools, you can use my simple tuning
  tools for ISDB-S/ISDB-T.
  * https://github.com/katsuster/sample_dvb_api
* Smartcard: Insert B-CAS card to smartcard reader

Example of scenario as follows:

    Tune to BS Premium
    
    # sample_dvb_api 0 S BS 3 0x4031
    ...
    
    Descramble it
    
    # arib_descramble /dev/dvb/adapter0/dvr0 hostip hostport
    PAT ver. 1
    --PMT prg:  103(0x0067) pid:0x01f0
    --PMT prg:  104(0x0068) pid:0x02f0
      PMT ver.16 prg:  103(0x0067) pid:0x01f0
      --ECM pid:0x0060
      --ES type:0x0002 pid:0x0100 ecm:0x0060
      --ES type:0x000f pid:0x0110 ecm:0x0060
      --ES type:0x0006 pid:0x0130 ecm:0x0060
      --ES type:0x0006 pid:0x0138 ecm:0x0060
      --ES type:0x000d pid:0x0140 ecm:0x0060
      --ES type:0x000d pid:0x0160 ecm:0x0060
      --ES type:0x000d pid:0x0161 ecm:0x0060
      --ES type:0x000d pid:0x0162 ecm:0x0060
      --ES type:0x000d pid:0x0170 ecm:0x0060
      --ES type:0x000d pid:0x0171 ecm:0x0060
    ...

If you want to use MPEG2-TS file, or standard input (stdin) instead of
tuner device, please specify arguments as follows:

    Use file
    
    # arib_descramble /path/to/file.ts hostip hostport
    
    Use stdin
    
    # arib_descramble - hostip hostport

You can replay the descrambled MPEG2-TS using VLC player or other nice players.

If you use VLC, please select "Media" - "Open Network Stream" and specify 
"udp://@:hostport" into address box to replay the stream comes from UDP.
