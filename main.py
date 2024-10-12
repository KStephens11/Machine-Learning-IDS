import pyshark
from session import Session
capture = pyshark.LiveCapture(interface='wlan0')


current_sessions = {}
bwd_count = 0
fwd_count = 0
del_session_count = 0
timeout = 100

for packet in capture:
    try:
        if "IP" in packet:
            timestamp = packet.sniff_time.timestamp()
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            proto_num = packet.ip.proto
                
            src_port = packet[packet.transport_layer].srcport
            dst_port = packet[packet.transport_layer].dstport
                
            fwd_session = src_ip + dst_ip + src_port + dst_port
            bwd_session = dst_ip + src_ip + dst_port + src_port
            
            # Check if fwd Session
            if fwd_session in current_sessions.keys():
                fwd_count +=1
                
                # Check for Reset or Fin flag
                if "TCP" in packet and (packet.tcp.flags_fin.int_value == 1 or packet.tcp.flags_reset.int_value == 1):
                    current_sessions[fwd_session].new_packet(packet)
                    del(current_sessions[fwd_session])
                    del_session_count += 1
                
                # Update packet
                else:
                    current_sessions[fwd_session].new_packet(packet)
                    
                    
            # Check if bwd Session
            elif bwd_session in current_sessions.keys():
                bwd_count += 1
                
                # Check for Reset or Fin flag
                if "TCP" in packet and (packet.tcp.flags_fin.int_value == 1 or packet.tcp.flags_reset.int_value == 1):
                    current_sessions[bwd_session].new_packet(packet)
                    del(current_sessions[bwd_session])
                    del_session_count += 1
                    
                # Update packet
                else:
                    current_sessions[bwd_session].new_packet(packet);

            # Make new Session      
            else:
                session = Session(packet)
                current_sessions[fwd_session] = session
            
            # Stats
            print(str(len(current_sessions)),'\t\t', str(fwd_count), '\t\t', str(bwd_count), '\t\t', str(del_session_count))
            for session_id, session_class in current_sessions.items():
                print(session_class.get_src_ip(),'\t\t', timestamp - session_class.get_packet_last_timestamp(), '\t\t', session_class.get_timestamp(), session_class.get_syn_count())
            print('\n')
        
        
        #Check all sessions for timeouts
        for session_id, session_class in current_sessions.copy().items():
            if timestamp - session_class.get_packet_last_timestamp() >= timeout:
                del(current_sessions[session_id])
                del_session_count += 1

    except Exception as error:
        print(error)