`(== 64 64)
(seed (in "/dev/urandom" (rd 8)))
(load "blake2s.l")
(load "functions.l")

(setq
   *Prv # WAmgVYXkbT2bCtdcDwolI88/iVi/aV3/PHcUBTQSYmo=
   (88 9 160 85 133 228 109 61 155 10 215 92 15 10 37 
      35 207 63 137 88 191 105 93 255 60 119 20 5 52 18 98 106 )
   *Pub # K5sF9yESrSBsOXPd6TcpKNgqoy1Ik3ZFKl4FolzrRyI=
   (43 155 5 247 33 18 173 32 108 57 115 221 233 55 41 
      40 216 42 163 45 72 147 118 69 42 94 5 162 92 235 71 34 )
   *RPub # qRCwZSKInrMAq5sepfCdaCsRJaoLe5jhtzfiw7CjbwM=
   (169 16 176 101 34 136 158 179 0 171 155 30 165 240 157 
      104 43 17 37 170 11 123 152 225 183 55 226 195 176 163 111 3 )
   *Pre # FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE= 
   (22 144 178 135 11 61 115 28 22 161 94 49 16 187 95 
      38 248 201 55 236 208 85 19 200 74 89 81 90 7 168 165 81 )

   *E (ephemrl-pair)
   *C (hash32 *CONSTRUCTION)
   *H (hash32 (append *C *IDENTIFIER))
   *H (hash32 (append *H *RPub))
   *K NIL
   *Nsend 0
   *Nrecv 0
   *IndexR NIL
   *Enc NIL
   *Dec NIL
   *Srv (server *DEMO_SERVER *DEMO_PORT) )

(sendto *Srv (start-handshake))
(fin-handshake (recvfrom *Srv)) 
# handshake done, keys splitted.

# send encrypted raw ping packet
(sendto *Srv (encryption *PING_DATA))

# retrieve ping response, decrypt and 
# find back 'WireGuard' label inside
(test
   *PING_LABEL
   (head
      (length *PING_LABEL)
      (nth (decryption (recvfrom *Srv)) 29) ) )

# send keepalive
(sendto *Srv (encryption))
(test *Nsend 2)
(test *Nrecv 1)

(msg 'OK)
(bye)

