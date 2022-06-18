-- voip.lua
-- Written by: Jason Garland <jgarland@jasongarland.com>

print("Starting voip.lua script.")


rex = require "rex_pcre"

--MySQL database connection
require "luasql.mysql"
env = assert (luasql.mysql())
con = assert (env:connect("voiper","voiper","password"))


do
        local voiperdir = os.getenv("voiperdir")
        local capturesdir = os.getenv("voiperdir") .. "/captures"
        dumpers = {}
        local frames = {}
        local rtp = {}
        last_packet = {}
        timeout = 300
        inin_callid = {}
        closed = {}
        files = {}
        files_path = {}
        --local tcp_src_f = Field.new("tcp.srcport")
        --local tcp_dst_f = Field.new("tcp.dstport")
        local udp_src_f = Field.new("udp.srcport")
        local udp_dst_f = Field.new("udp.dstport")
        local rtp_ssrc_f = Field.new("rtp.ssrc")
        local rtp_setup_frame_f = Field.new("rtp.setup-frame")
        local t38_setup_frame_f = Field.new("t38.setup-frame")
        local rtcp_setup_frame_f = Field.new("rtcp.setup-frame")
        local rtcp_ssrc_jitter_f = Field.new("rtcp.ssrc.jitter")
        local rtcp_ssrc_fraction_f = Field.new("rtcp.ssrc.fraction")
        local rtcp_ssrc_identifier_f = Field.new("rtcp.ssrc.identifier")
        local sip_callid_f = Field.new("sip.Call-ID")
        local sip_cseq_method_f = Field.new("sip.CSeq.method")
        local sip_status_code_f = Field.new("sip.Status-Code")

        local sip_contact_addr_f = Field.new("sip.contact.addr")
        local sip_request_line_f = Field.new("sip.Request-Line")
        local sip_from_addr_f = Field.new("sip.from.addr")

        local sdp_connection_info_address_f = Field.new("sdp.connection_info.address")
        local raw_sip_line_f = Field.new("raw_sip.line")
        local function init_listener()
                local tap = Listener.new("ip", "(rtp or rtcp or t38) or (sip and ((sip.CSeq.method != REGISTER) and (sip.CSeq.method != OPTIONS))) ")
                -- we will be called once for every IP Header.
                -- If there's more than one IP header in a given packet we'll dump the packet once per every header
                function tap.packet(pinfo,tvb,ip)
                        local ip_src, ip_dst = tostring(ip.ip_src), tostring(ip.ip_dst)
                        --local rtp_ssrc, rtp_setup_frame = rtp_ssrc_f(), rtp_setup_frame_f()
                        local rtp_setup_frame,rtp_ssrc = rtp_setup_frame_f(), rtp_ssrc_f()
                        local t38_setup_frame = t38_setup_frame_f()
                        local sip_cseq_method, sip_status_code, sip_callid, sdp_connection_info_address, raw_sip_line = sip_cseq_method_f(), sip_status_code_f(), sip_callid_f(), sdp_connection_info_address_f(), raw_sip_line_f()
                        local sip_contact_addr, sip_request_line, sip_from_addr = sip_contact_addr_f(), sip_request_line_f(), sip_from_addr_f() 
                        local rtcp_setup_frame, rtcp_ssrc_jitter, rtcp_ssrc_fraction, rtcp_ssrc_identifier = rtcp_setup_frame_f(), rtcp_ssrc_jitter_f(), rtcp_ssrc_fraction_f(), rtcp_ssrc_identifier_f()
                        local frame = tostring(pinfo.number)
                        local src_dmp, dst_dmp, rtp_dmp, sip_dmp
                                                
                        if sdp_connection_info_address then
                                --print("Frame: " .. frame .. " = " .. tostring(sip_callid))
                                frames[frame] = tostring(sip_callid)
                        end
                                                                        
                        if rtcp_setup_frame then
                                if not (frames[tostring(rtcp_setup_frame)] == nil) then
                                        sip_callid = frames[tostring(rtcp_setup_frame)]
                                end
                        end
                                                                        
                        if t38_setup_frame then
                                if not (frames[tostring(t38_setup_frame)] == nil) then
                                        sip_callid = frames[tostring(t38_setup_frame)]
                                end
                        end
                                                                                                
                        --if rtp_setup_frame then
                                if not (frames[tostring(rtp_setup_frame)] == nil) then
                                        sip_callid = frames[tostring(rtp_setup_frame)]
                                        rtp[tostring(rtp_ssrc)] = sip_callid
                                -- else
                                        -- rtp_dmp = dumpers[tostring(rtp_ssrc)]
                                        -- if not rtp_dmp then
                                        --         rtp_dmp = Dumper.new_for_current( capturesdir .. "/rtp/" .. tostring(rtp_ssrc) .. ".pcap" )
                                        --         dumpers[tostring(rtp_ssrc)] = rtp_dmp
                                        -- end
                                        -- rtp_dmp:dump_current()
                                        -- rtp_dmp:flush()
                                end
                        --end
                        
                        if (sip_callid == nil) then
                                if (rtp_ssrc) then
                                        sip_callid = rtp[tostring(rtp_ssrc)]
                                        --if not (sip_callid == nil) then print("SSRC: " .. tostring(rtp_ssrc) .. " = " .. sip_callid) end
                                end
                        end
                                                                        
                        if sip_callid then
                                if not ((closed[tostring(sip_callid)] == true)) then
                                        --check_age()
                                        if (files[tostring(sip_callid)] == nil) then
                                                files_path[tostring(sip_callid)] = os.date("%Y", pinfo.abs_ts) .. "/" .. os.date("%m", pinfo.abs_ts) .. "/" .. os.date("%d", pinfo.abs_ts) .. "/" .. os.date("%H", pinfo.abs_ts) .. "/"
                                        os.execute("mkdir -p " .. capturesdir .. "/" .. files_path[tostring(sip_callid)])
                                        files[tostring(sip_callid)] = os.date("%Y%m%d%H%M%S", pinfo.abs_ts) .. "-" .. tostring(sip_callid) .. ".pcap"
                                        -- print("Creating: " .. files_path[tostring(sip_callid)] .. files[tostring(sip_callid)])
                                        res = assert (con:execute(string.format([[
                                        INSERT INTO calls
                                                (filepath, filename, callid, state)
                                                VALUES ('%s', '%s', '%s', '%s')
                                                ]], files_path[tostring(sip_callid)], files[tostring(sip_callid)], tostring(sip_callid), "open")
                                                                                                                                ))
                                                                        
                                end
                                                                        
                                -- print(tostring(sip_callid))
                                sip_dmp = dumpers[tostring(sip_callid)]
                                if not sip_dmp then
                                        print("Opening: " .. files_path[tostring(sip_callid)] .. files[tostring(sip_callid)])
                                        sip_dmp = Dumper.new_for_current( capturesdir .. "/" .. files_path[tostring(sip_callid)] .. files[tostring(sip_callid)] )
                                        dumpers[tostring(sip_callid)] = sip_dmp
                                end
                                sip_dmp:dump_current()
                                sip_dmp:flush()
                                last_packet[tostring(sip_callid)] = os.clock()
                                if (tostring(sip_cseq_method) == "BYE" and tostring(sip_status_code) == "200") then
                                        sip_dmp:close()
                                        sip_dmp = nil
                                        mark_closed(sip_callid)
                                end
                                if (tostring(sip_cseq_method) == "INVITE" and tostring(sip_status_code) == "487") then
                                        sip_dmp:close()
                                        sip_dmp = nil
                                        mark_closed(sip_callid)
                                end
                                else
                                        print("Ignoring packet after " .. tostring(sip_callid) .. " was closed.")
                                end
                        end
                                                                        
                                                                        
                        if raw_sip_line_f() then
                                local line = {raw_sip_line_f()}
                                for i=1,#line do
                                        line[i] = tostring(line[i])
                                        local inin_callid_start, inin_callid_stop, inin_callid_header, inin_callid_value = rex.find(line[i], '^(ININCrn|x-inin-crn): ([0-9]*)\\\\r\\\\n$')
                                        if inin_callid_value then
                                                if not inin_callid[tostring(sip_callid)] then
                                                        inin_callid[tostring(sip_callid)] = inin_callid_value
                                                        -- print(inin_callid_header .. ": " .. inin_callid_value)
                                                        res = assert (con:execute(string.format([[
                                                                UPDATE calls
                                                                SET `inin_callid` = '%s' WHERE `callid` = '%s']], inin_callid[tostring(sip_callid)], tostring(sip_callid))
                                                                ))
                                                end
                                                break
                                        end
                                end
                        end
                end


                function check_age()
                        for item in pairs(last_packet) do
                                local age = os.difftime(os.clock(), last_packet[tostring(item)])
                                if ( age >= timeout ) then
                                        print("Timeout: " .. item .. " because age is " .. age .. " seconds.")
                                        --return true
                                        mark_closed(item)
                                        --dumper = dumpers[tostring(item)]
                                        --print("Dumper: " .. tostring(dumper))
                                        --dumper:flush()
                                        --dumper:close()
                                        --dumpers[tostring(item)] = nil

                                        --dumpers[tostring(item)]:close()
                                        --dumpers[tostring(item)] = nil
                                end
                        end
                end

                function mark_closed(sip_callid)
                        print("Closing: " .. files_path[tostring(sip_callid)] .. files[tostring(sip_callid)])
                        res = assert (con:execute(string.format([[
                                UPDATE calls
                                SET `state` = 'closed' WHERE `callid` = '%s' AND `filepath` = '%s' AND `filename` = '%s']], tostring(sip_callid), files_path[tostring(sip_callid)], files[tostring(sip_callid)])
                                ))
                        closed[tostring(sip_callid)] = true
                        inin_callid[tostring(sip_callid)] = nil
                        last_packet[tostring(sip_callid)] = nil
                        files[tostring(sip_callid)] = nil
                        files_path[tostring(sip_callid)] = nil
                end

                function tap.draw()
                        -- The show is over. Close the database connection and flush the buffers.
                        for item in pairs(closed) do
                                print("cleaning up: " .. item)
                                dumpers[tostring(item)] = nil
                        end

                        for item,dumper in pairs(dumpers) do
                                print("Flushing: " .. files_path[tostring(item)] .. files[tostring(item)])
                                dumper:flush()
                                mark_closed(item)
                        end

                        -- Close the database connection
                        con:close()
                        env:close()
                end

                function tap.reset()
                        for item,dumper in pairs(dumpers) do
                                mark_closed(item)
                                dumper:close()
                                print("Tap reset")
                        end
                        dumpers = {}
                end
        end
        init_listener()
end
