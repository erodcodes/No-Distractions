import pydivert

# List of websites and IPs to block
blocked_sites = [
    "youtube.com",

]
blocked_ips = [
    "152.10.2.222",  # Example IP for youtube.com
    "142.250.72.238",  # Example IP for googlevideo.com
]

def block_websites():
    """
    Block traffic to specified websites and IPs using Windows Filtering Platform (WFP).
    """
    # Filter HTTP (port 80), HTTPS (port 443), and QUIC (UDP/443) traffic
    with pydivert.WinDivert("tcp.DstPort == 80 or tcp.DstPort == 443 or udp.DstPort == 443") as w:
        print("Starting website blocker...")
        for packet in w:
            # Block by domain (SNI or HTTP Host header)
            sni = extract_sni(packet.payload)
            if sni and any(site in sni for site in blocked_sites):
                print(f"Blocked HTTPS/QUIC request to {sni}")
                continue  # Drop the packet

            # Block by IP address
            if packet.dst_addr in blocked_ips:
                print(f"Blocked traffic to IP {packet.dst_addr}")
                continue  # Drop the packet

            w.send(packet)  # Allow other traffic



def extract_sni(payload):
    """
    Extract the Server Name Indication (SNI) field from a TLS handshake.
    """
    try:
        # Check if the payload is large enough to be a TLS handshake
        if len(payload) < 5:
            return None

        # TLS handshake starts with 0x16 (Content Type: Handshake)
        if payload[0] != 0x16:
            return None

        # Skip the TLS header (5 bytes) and Handshake Type (1 byte)
        offset = 5 + 1

        # Check if the payload is large enough to contain the length fields
        if len(payload) < offset + 3 + 2:
            return None

        # Skip the length fields (3 bytes for Handshake Protocol, 2 bytes for Handshake Message)
        offset += 3 + 2

        # Check if the payload is large enough to contain the ClientHello random (32 bytes)
        if len(payload) < offset + 32:
            return None

        # Skip the ClientHello random (32 bytes)
        offset += 32

        # Check if the payload is large enough to contain the session ID length (1 byte)
        if len(payload) < offset + 1:
            return None

        # Skip the session ID length (1 byte + session ID)
        session_id_length = payload[offset]
        offset += 1 + session_id_length

        # Check if the payload is large enough to contain the cipher suites length (2 bytes)
        if len(payload) < offset + 2:
            return None

        # Skip the cipher suites length (2 bytes + cipher suites)
        cipher_suites_length = int.from_bytes(payload[offset:offset + 2], byteorder="big")
        offset += 2 + cipher_suites_length

        # Check if the payload is large enough to contain the compression methods length (1 byte)
        if len(payload) < offset + 1:
            return None

        # Skip the compression methods length (1 byte + compression methods)
        compression_methods_length = payload[offset]
        offset += 1 + compression_methods_length

        # Check if the payload is large enough to contain the extensions length (2 bytes)
        if len(payload) < offset + 2:
            return None

        # Extract the extensions length (2 bytes)
        extensions_length = int.from_bytes(payload[offset:offset + 2], byteorder="big")
        offset += 2

        # Iterate through extensions to find the SNI
        while offset < len(payload):
            # Check if the payload is large enough to contain the extension type (2 bytes)
            if len(payload) < offset + 2:
                return None

            # Extract extension type (2 bytes)
            extension_type = int.from_bytes(payload[offset:offset + 2], byteorder="big")
            offset += 2

            # Check if the payload is large enough to contain the extension length (2 bytes)
            if len(payload) < offset + 2:
                return None

            # Extract extension length (2 bytes)
            extension_length = int.from_bytes(payload[offset:offset + 2], byteorder="big")
            offset += 2

            # Check if this is the SNI extension (type 0x0000)
            if extension_type == 0x0000:
                # Check if the payload is large enough to contain the SNI list length (2 bytes)
                if len(payload) < offset + 2:
                    return None

                # Skip the SNI list length (2 bytes)
                offset += 2

                # Check if the payload is large enough to contain the SNI type (1 byte)
                if len(payload) < offset + 1:
                    return None

                # Extract the SNI type (1 byte)
                sni_type = payload[offset]
                offset += 1

                # Check if the payload is large enough to contain the SNI length (2 bytes)
                if len(payload) < offset + 2:
                    return None

                # Extract the SNI length (2 bytes)
                sni_length = int.from_bytes(payload[offset:offset + 2], byteorder="big")
                offset += 2

                # Check if the payload is large enough to contain the SNI hostname
                if len(payload) < offset + sni_length:
                    return None

                # Extract the SNI hostname
                sni_hostname = payload[offset:offset + sni_length].decode("utf-8")
                return sni_hostname

            # Move to the next extension
            offset += extension_length

        return None
    except Exception as e:
        print(f"Error extracting SNI: {e}")
        return None

block_websites()