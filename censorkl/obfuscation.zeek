@load base/protocols/conn
@load base/protocols/ssl
@load policy/frameworks/packet-filter/shunt

module TLSFP;

export {
        redef enum Log::ID += {TLSLOG, PKTLOG};

        type Packet: record {
                conn_id:        string;
                idx:            count;

                timestamp:      time;
                direction:      count;
                size:           count;
        } &log;

        type Info: record {
                logged:         bool &default=F;

                conn_id:        string &log;

                syn_ts:         time &log;
                synack_ts:      time &log;
                ack_ts:         time &log &optional;

                version:        string &log;

                client_hello:   count &log;
                server_hello:   count &log;
                ssl_est:        count &log;

                len:            count &log;

                packets:        vector of Packet;               
        };

        option packets_to_observe = 50;
        option allow_shorter_flows = T;

        global next_seq: table[string, bool] of count;
        global errors: table[string] of count &default_insert=0;
}

redef record connection += { tlsfingerprint: Info &optional; };

redef PacketFilter::max_bpf_shunts = 1000000;
redef Analyzer::disable_all = T;
redef tcp_SYN_ack_ok = F;

event zeek_init() {
        # Enable only the SSL protocol analyzer
        Analyzer::enable_analyzer(Analyzer::ANALYZER_SSL);

        # Disable unnecessary logs
        Log::disable_stream(Conn::LOG);
        Log::disable_stream(SSL::LOG);
        Log::disable_stream(X509::LOG);
        Log::disable_stream(Files::LOG);
        Log::disable_stream(OCSP::LOG);
        Log::disable_stream(PacketFilter::LOG);
        Log::disable_stream(Reporter::LOG);
        Log::disable_stream(Weird::LOG);
        Log::disable_stream(Notice::LOG);
        
        Log::create_stream(TLSFP::TLSLOG, [$columns=Info, $path="obfuscation"]);
        local f = Log::get_filter(TLSFP::TLSLOG, "default");
        f$config = table(["tsv"] = "T");
        Log::add_filter(TLSFP::TLSLOG, f);

        Log::create_stream(TLSFP::PKTLOG, [$columns=Packet, $path="packets"]);
        f = Log::get_filter(TLSFP::PKTLOG, "default");
        f$config = table(["tsv"] = "T");
        Log::add_filter(TLSFP::PKTLOG, f);
}

function is_tcp_handshake_complete(c: connection) : bool {
        if (!c?$tlsfingerprint) return F;
        return c$tlsfingerprint?$syn_ts && c$tlsfingerprint?$synack_ts && c$tlsfingerprint?$ack_ts;
}

function discard_flow(c: connection, reason: string) {
        if (c?$tlsfingerprint) c$tlsfingerprint$logged = T;
        PacketFilter::shunt_conn(c$id);
        errors[reason] += 1;
        print c$id, reason;
}

function extract_packet_features(c: connection, is_orig: bool, payload: string) {
        local packet : Packet = Packet(
                $conn_id = c$uid,
                $idx = |c$tlsfingerprint$packets|,
                $timestamp = network_time(),
                $direction = |is_orig|,
                $size = |payload|
        );

        # If the first data packet is not client-to-server, we can stop monitoring.
        # Or, if a data packet has bad timestamp ordering, we stop monitoring.
        if (packet$idx == 0 && (!is_orig || /^\x16\x03[\x00-\x03]/ !in payload)) {
                discard_flow(c, "missed TLS Client Hello");
                return;
        }
        else if (packet$idx > 0) {
                if (packet$timestamp < c$tlsfingerprint$packets[packet$idx - 1]$timestamp) {
                        discard_flow(c, "saw data packets out-of-order");
                        return;
                }
                # If we see an Application Data TLS record, check if we even saw the handshake
                # TLS1.3 sends part of handshake in encrypted Application Data records, so
                # cannot discard flow for SSL not yet being established.
                else if (/^\x17\x03[\x00-\x03]/ in payload) {
                        # check for Client Hello again in case we saw first packet but missed
                        # second packet
                        if (!c$tlsfingerprint?$client_hello) discard_flow(c, "missed TLS Client Hello");
                        else if (!c$tlsfingerprint?$server_hello) discard_flow(c, "missed TLS Server Hello");
                }
        }

        c$tlsfingerprint$packets += packet;
}

function delete_sequence_number_state(id: string) {
        delete next_seq[id, T];
        delete next_seq[id, F];
}

function log_flow(c: connection) {
        if (!c?$tlsfingerprint) return;

        c$tlsfingerprint$len = |c$tlsfingerprint$packets|;

        delete_sequence_number_state(c$uid);

        # We no longer need to monitor this connection. Not all connections 
        # (e.g., IPv6) can be shunted due to limitations of BPF, so we must 
        # maintain the boolean as well.
        discard_flow(c, "success");

        # Basic sanity checks: if we missed a TCP or TLS handshake packet, or 
        # we observed handshake packets in the wrong order, or we do not see
        # at least one data packet after the TLS handshake, discard the flow.
        if (!c$tlsfingerprint?$syn_ts ||
                !c$tlsfingerprint?$synack_ts ||
                !c$tlsfingerprint?$ack_ts ||
                !c$tlsfingerprint?$client_hello || 
                !c$tlsfingerprint?$server_hello || 
                !c$tlsfingerprint?$ssl_est ||
                c$tlsfingerprint$syn_ts > c$tlsfingerprint$synack_ts ||
                c$tlsfingerprint$synack_ts > c$tlsfingerprint$ack_ts ||
                c$tlsfingerprint$len - 1 <= c$tlsfingerprint$ssl_est)  
        {
                #print "Rejected", c$id, c$tlsfingerprint;
                return;
        }

        # Log.
        Log::write(TLSFP::TLSLOG, c$tlsfingerprint);
        for (idx in c$tlsfingerprint$packets) Log::write(TLSFP::PKTLOG, c$tlsfingerprint$packets[idx]);
}

event connection_SYN_packet(c: connection, pkt: SYN_packet) {
        if (pkt$is_orig) {
                local info : Info;
                info$conn_id = c$uid;
                info$syn_ts = network_time();
                info$packets = vector();
                c$tlsfingerprint = info;
        }
}

event connection_established(c: connection) {
        if (c?$tlsfingerprint) {
                c$tlsfingerprint$synack_ts = network_time();
                # If we missed the SYN packet or the SYN+ACK arrived at the tap first, stop monitoring
                if (!c$tlsfingerprint?$syn_ts) discard_flow(c, "missed SYN");
                else if (c$tlsfingerprint$syn_ts > c$tlsfingerprint$synack_ts) discard_flow(c, "saw SYN+ACK before SYN");
        }
}

event connection_first_ACK(c: connection) {
        if (c?$tlsfingerprint) {
                c$tlsfingerprint$ack_ts = network_time();
                # If we missed the SYN+ACK packet or the ACK arrived at the tap first, stop monitoring
                if (!c$tlsfingerprint?$synack_ts) discard_flow(c, "missed SYN+ACK");
                else if (c$tlsfingerprint$synack_ts > c$tlsfingerprint$ack_ts) discard_flow(c, "saw ACK before SYN+ACK");
        }
}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) {
        if (!c?$tlsfingerprint || c$tlsfingerprint$logged) return;
        else if (!is_tcp_handshake_complete(c)) {
                discard_flow(c, "incomplete TCP handshake");
                return;
        }

        c$tlsfingerprint$client_hello = |c$tlsfingerprint$packets| - 1;
}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) {
        if (!c?$tlsfingerprint || c$tlsfingerprint$logged) return;
        else if (!is_tcp_handshake_complete(c)) {
                discard_flow(c, "incomplete TCP handshake");
                return;
        }
        # TODO: add case here to check server hello index before or at client hello index
        c$tlsfingerprint$server_hello = |c$tlsfingerprint$packets| - 1;
}

event ssl_established(c: connection) {
        if (!c?$tlsfingerprint || c$tlsfingerprint$logged) return;
        else if (!is_tcp_handshake_complete(c)) {
                discard_flow(c, "incomplete TCP handshake");
                return;
        }

        c$tlsfingerprint$ssl_est = |c$tlsfingerprint$packets| - 1;
        c$tlsfingerprint$version = c$ssl$version;
}

event connection_state_remove(c: connection) {
        if (c?$tlsfingerprint && 
                (0 < |c$tlsfingerprint$packets|) &&
                (|c$tlsfingerprint$packets| < packets_to_observe)) 
        {
                if (allow_shorter_flows) log_flow(c);
                else discard_flow(c, "flow too short");
        }

        delete_sequence_number_state(c$uid);
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) &priority=10 {
        if (! c?$tlsfingerprint) return;
        # Ignore packets from connections that we no longer need to monitor.
        if (c$id in PacketFilter::current_shunted_conns() || (c?$tlsfingerprint && c$tlsfingerprint$logged)) return;

        # Ignore non-data packets. For TCP, control packets of shunted connections are
        # still allowed through to determine when the connection is over.
        if (len == 0) return;
        if (!c$tlsfingerprint?$syn_ts || !c$tlsfingerprint?$synack_ts || !c$tlsfingerprint?$ack_ts) return;

        if ([c$uid, is_orig] !in next_seq) next_seq[c$uid, is_orig] = seq;

        # Ensure that the flow is "clean" in that there are no retransmissions, drops, or
        # out-of-order segments. If one of these occurred, the next observed sequence number
        # will not be what was expected.
        if ( seq != next_seq[c$uid, is_orig] ) {
                # print c$id, fmt("GAP/OOS: %s seq=%d expected=%d",
                #   is_orig ? "orig" : "resp", seq, next_seq[c$uid, is_orig]), c$tlsfingerprint, flags, len;
                
                discard_flow(c, "unexpected sequence number");

                # delete from table
                delete_sequence_number_state(c$uid);

                return;
        }

        next_seq[c$uid, is_orig] = seq + len;

        extract_packet_features(c, is_orig, payload);

        if (|c$tlsfingerprint$packets| == packets_to_observe) log_flow(c);
}
