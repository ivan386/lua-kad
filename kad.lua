local socket  = require "socket"
local deflate = require "deflate.LibDeflate"
require "lua-asp.advanced-string-pack"
require "lua-md5.md5"
require "lua-md4.md4"
require "lua-rc4.rc4"

-- первый байт
local ED2K_PROTOCOL_KAD = 0xE4        -- обычный пакет
local ED2K_PROTOCOL_KAD_PACKED = 0xE5 -- сжатый пакет
-- Другие значения означают что пакет зашифрован


-- второй байт пакета (не сжимается)
local KADEMLIA2_REQ	= 0x21 -- поиск ближайших узлов
local KADEMLIA2_RES = 0x29 -- ответ на поиск узлов
local KADEMLIA2_SEARCH_KEY_REQ = 0x33    -- поиск файлов по слову(keyword)
local KADEMLIA2_SEARCH_SOURCE_REQ = 0x34 -- поиск источников файла
local KADEMLIA2_SEARCH_RES = 0x3B        -- ответ с результатами поиска

local KADEMLIA_FIND_VALUE =	0x02 -- первый байт KADEMLIA2_REQ это количество узлов запрашиваемое при поиске

local kad2_packet_format = ([[
	(B)
		{
			ED2K_PROTOCOL_KAD:
				(B)
					{
						 KADEMLIA2_REQ               : B c16
						,KADEMLIA2_RES               : c16 [B] {c16 c4 <H <H B}
						,KADEMLIA2_SEARCH_KEY_REQ    : c16 ]]--[[(<H) {0x8000: (B) {0: B, <s2, <s2 <s2, <L B <s2, 8: <I8 B <s2} }]]..[[
						,KADEMLIA2_SEARCH_SOURCE_REQ : c16 <H <I8
						,KADEMLIA2_SEARCH_RES        : c16 c16 [<H] { c16 [B] { (B) <s2 { c16, <s2, <L, <f, B,, <s4, <H, B, s1, <I8 } } }
					}
			,ED2K_PROTOCOL_KAD_PACKED: B
			,*: c2
		}
]])
:gsub("KADEMLIA2_SEARCH_SOURCE_REQ", KADEMLIA2_SEARCH_SOURCE_REQ)
:gsub("ED2K_PROTOCOL_KAD_PACKED", ED2K_PROTOCOL_KAD_PACKED)
:gsub("KADEMLIA2_SEARCH_KEY_REQ", KADEMLIA2_SEARCH_KEY_REQ)
:gsub("KADEMLIA2_SEARCH_RES", KADEMLIA2_SEARCH_RES)
:gsub("ED2K_PROTOCOL_KAD", ED2K_PROTOCOL_KAD)
:gsub("KADEMLIA2_REQ", KADEMLIA2_REQ)
:gsub("KADEMLIA2_RES", KADEMLIA2_RES)


--[[
 с16 это строка в 16 байт. Ей может быть ID получателя либо целевой хеш
 с4 это ipv4 адрес(перевёрнутый) за ним сразу следуют два <H это два номера порта UDP и TCP
--]]

-- формат файла списка узлов
local bootstrap_list_format = [[
	(*[<L]{c16 c4 <H <H B})
	{
		0:
			(<L)
			[<L]
			{
				 1: c16 c4 <H <H B
				,2: c16 c4 <H <H B c4 c4 B
			}
	}
]]

local MAGICVALUE_UDP_SYNC_CLIENT = ("<I4"):pack(0x395F2EC1)

math.randomseed(os.time() + os.clock())
local my_key = string.pack("<L", math.random(1 << 32 - 1))

function send_packet(data, receiver_id, sender_key, ip, port, socket)
	-- У первого байта первые два бита это тип ключа.
	-- В случае использования в качестве ключа ID узла значение этих бит равно 0.
	
	local first_byte = math.random(0, 255) & (255 << 2)
	while first_byte == ED2K_PROTOCOL_KAD do
		first_byte = math.random(0, 255) & (255 << 2)
	end
	
	local two_random_bytes = string.pack("<I2", math.random(1<<16 - 1))  
	
	-- дополняем
	-- magic_value(<I4) padding(B) receiver_key(<I4) sender_key(<I4) data
	data = MAGICVALUE_UDP_SYNC_CLIENT.."\0".."\0\0\0\0"..sender_key..data
	
	-- шифруем
	-- в данном случае для шифрования мы используем ID получателя
	data = rc4(md5(receiver_id..two_random_bytes), data)
	
	-- дополняем шифрованный пакет необходимыми для расшифрофки данными
	data = string.char(first_byte)..two_random_bytes..data
	
	-- отправляем
	socket:sendto(data, ip, port)
end


function receive_packet(socket)
	local data, ip, port = socket:receivefrom()
	
	if data and #data > 3 + 4 + 1 + 4 + 4 + 2 and data:byte() & 3 == 2 then -- 2 означает что при шифровании использовался наш ключ
		
		-- расшифровываем
		local edata = rc4(md5(my_key..data:sub(2,3)), data, 4)
		
		-- проверяем
		local magic_value, next_pos = ("c4"):unpack(edata)
		if magic_value == MAGICVALUE_UDP_SYNC_CLIENT then
			_, receiver_key, next_pos = ("s1 c4"):unpack(edata, next_pos)
			
			if receiver_key == my_key then
				data = edata:sub(next_pos + 4)
			end
		end
	end

	if data and data:byte() == ED2K_PROTOCOL_KAD then
		return data, ip, port
	end

	if data and data:byte() == ED2K_PROTOCOL_KAD_PACKED then -- сжатый пакет
		
		-- разжимаем
		local cdata, err = deflate:DecompressZlib(data:sub(3))
		if cdata then
			-- меняем 
			return string.char(ED2K_PROTOCOL_KAD, data:byte(2))..cdata, ip, port
		end
	end	
end

function unpack_ip(data)
	return ("%u.%u.%u.%u"):format(data:reverse():byte(1,4))
end

function reverse_hash(hash)
	return string.pack("<L<L<L<L", string.unpack(">L>L>L>L", hash))
end

local find_value_packet
local search_packet
local search_target
local checked_peers = {}

function check_peer(peer, udp_port)
	local peer_id, peer_ip, peer_udp_port = table.unpack(peer)
	if not checked_peers[peer_ip] then
		checked_peers[peer_ip] = true
		send_packet(find_value_packet..peer_id, peer_id, my_key, unpack_ip(peer_ip), peer_udp_port, udp_port)
		if search_target:byte(4) == peer_id:byte(4) then
			send_packet(search_packet, peer_id, my_key, unpack_ip(peer_ip), peer_udp_port, udp_port)
		end
	end
end

function check_peers(peers, udp_port)
	for _, peer in ipairs(peers) do
		check_peer(peer, udp_port)
		check_responces(udp_port)
	end
end
local TAGS = {
 ["\x01"] = "TAG_FILENAME"	-- <string>
,["\x02"] = "TAG_FILESIZE"	-- <uint32>
,["\x3A"] = "TAG_FILESIZE_HI"	-- <uint32>
,["\x03"] = "TAG_FILETYPE"	-- <string>
,["\x04"] = "TAG_FILEFORMAT"	-- <string>
,["\x05"] = "TAG_COLLECTION"
,["\x06"] = "TAG_PART_PATH"	-- <string>
,["\x07"] = "TAG_PART_HASH"
,["\x08"] = "TAG_COPIED"	-- <uint32>
,["\x09"] = "TAG_GAP_START"	-- <uint32>
,["\x0A"] = "TAG_GAP_END"	-- <uint32>
,["\x0B"] = "TAG_DESCRIPTION"	-- <string>
,["\x0C"] = "TAG_PING"
,["\x0D"] = "TAG_FAIL"
,["\x0E"] = "TAG_PREFERENCE"
,["\x0F"] = "TAG_PORT"
,["\x10"] = "TAG_IP_ADDRESS"
,["\x11"] = "TAG_VERSION"	-- <string>
,["\x12"] = "TAG_TEMPFILE"	-- <string>
,["\x13"] = "TAG_PRIORITY"	-- <uint32>
,["\x14"] = "TAG_STATUS"	-- <uint32>
,["\x15"] = "TAG_SOURCES"	-- <uint32>
,["\x15"] = "TAG_AVAILABILITY"	-- <uint32>
,["\x16"] = "TAG_PERMISSIONS"
,["\x16"] = "TAG_QTIME"
,["\x17"] = "TAG_PARTS"
,["\x33"] = "TAG_PUBLISHINFO"	-- <uint32> = <namecount uint8><publishers uint8><trustvalue*100 uint16>
,["\x37"] = "TAG_KADAICHHASHRESULT"		-- <Count 1>{<Publishers 1><AICH Hash> Count}
,["\xD0"] = "TAG_MEDIA_ARTIST"	-- <string>
,["\xD1"] = "TAG_MEDIA_ALBUM"	-- <string>
,["\xD2"] = "TAG_MEDIA_TITLE"	-- <string>
,["\xD3"] = "TAG_MEDIA_LENGTH"	-- <uint32> !!!
,["\xD4"] = "TAG_MEDIA_BITRATE"	-- <uint32>
,["\xD5"] = "TAG_MEDIA_CODEC"	-- <string>
,["\xF2"] = "TAG_KADMISCOPTIONS"	-- <uint8>
,["\xF3"] = "TAG_ENCRYPTION"	-- <uint8>
,["\xF7"] = "TAG_FILERATING"	-- <uint8>
,["\xF8"] = "TAG_BUDDYHASH"	-- <string>
,["\xF9"] = "TAG_CLIENTLOWID"	-- <uint32>
,["\xFA"] = "TAG_SERVERPORT"	-- <uint16>
,["\xFB"] = "TAG_SERVERIP"	-- <uint32>
,["\xFC"] = "TAG_SOURCEUPORT"	-- <uint16>
,["\xFD"] = "TAG_SOURCEPORT"	-- <uint16>
,["\xFE"] = "TAG_SOURCEIP"	-- <uint32>
,["\xFF"] = "TAG_SOURCETYPE"	-- <uint8>
}
function string.tohex(data)
	local hex = data:gsub(".", function(chr) return ("%02X"):format(chr:byte()) end)
    return hex
end

function string.fromhex(hex)
	local zero = ("0"):byte()
	local a = ("A"):byte()
	local data = hex:gsub("..", function(hex)
		local b1, b2 = hex:byte(1, 2)
		return string.char(   (b1 >= a and 10 + b1 - a or b1 - zero) << 4 
		                    | (b2 >= a and 10 + b2 - a or b2 - zero)      )
	end)
    return data
end

local base32="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

function string.tob32(data)
	local byte=0
	local bits=0
	local i=0
	local b32 = data:gsub(".", function(chr)
		local rez = ""
		byte=byte*256+string.byte(chr)
		bits=bits+8
		repeat 
			bits=bits-5
			local mul=(2^(bits))
			local b32n=math.floor(byte/mul)
			byte=byte-(b32n*mul)
			b32n=b32n+1
			rez=rez..string.sub(base32,b32n,b32n)
		until bits<5
		return rez
	end)
	if bits>0 then
		local b32n= math.fmod(byte*(2^(5-bits)),32)
		b32n=b32n+1
		b32=b32..string.sub(base32,b32n,b32n)
	end
    return b32
end

local printed = {}
local ed2k_link_only, magnet_link_only, tags_only

function print_results(results)
	for _, result in ipairs(results) do
		
		if not printed[result[1]] then
			printed[result[1]] = true
			local id_or_hash, source, aich, file_name, file_size, bitrate, length = reverse_hash(result[1]):tohex(), ""
			if not (ed2k_link_only or magnet_link_only) then
				io.stdout:write("\n")
			end
			for _, tag in ipairs(result[3]) do
			
				local tag_name, tag_value = TAGS[tag[2]] or tag[2], tag[3][1]
			
				if tag_name == "TAG_FILENAME" then
					file_name = tag_value
				elseif tag_name == "TAG_FILESIZE" then
					file_size = tag_value
				elseif tag_name == "TAG_MEDIA_BITRATE" then
					bitrate = tag_value * 1024
				elseif tag_name == "TAG_SOURCEIP" then
					source = table.concat({(">L"):pack(tag_value):byte(1,4)}, ".") .. (source or "")
				elseif tag_name == "TAG_SOURCEPORT" then
					source = (source or "") .. ":" .. tag_value
				elseif tag_name == "TAG_KADAICHHASHRESULT" then
					local aich_result = ("[B]{B c20}"):unpack(tag_value, 1, true)
					if aich_result and aich_result[1] > 0 then
						aich = aich_result[2][1][2]:tob32()
					end
				end
				
				if not (ed2k_link_only or magnet_link_only) then
					if tag_name == "TAG_KADAICHHASHRESULT" then
						local aich_result = ("[B]{B c20}"):unpack(tag_value, 1, true)
						io.stdout:write(tag_name, ":\t", aich_result[1])
						for _, aich_variant in ipairs(aich_result[2]) do
							io.stdout:write("\n\t\t", aich_variant[1],  ", ", aich)
						end
						
					elseif tag_name == "TAG_MEDIA_BITRATE" then
						io.stdout:write(tag_name, ":\t", tag_value * 1024)
						if file_size and length then
							io.stdout:write(" (", math.ceil(file_size * 8 / length), ")")
						end
						
					elseif tag_name == "TAG_MEDIA_LENGTH" then
						length = tag_value
						io.stdout:write(tag_name, ":\t", math.floor(length / 60^2), ":", math.floor(length / 60) % 60, ":", length % 60)
						
					elseif tag_name == "TAG_PUBLISHINFO" then
						io.stdout:write(tag_name, ":\t", tag_value >> 24 & 255, "(name count), ", tag_value >> 16 & 255, "(publishers), ", (tag_value & 0xFFFF) / 100, "(trustvalue)")
						
					elseif tag_name == "TAG_SOURCEIP" or tag_name == "TAG_SERVERIP" then	
						io.stdout:write(tag_name, ":\t", table.concat({(">L"):pack(tag_value):byte(1,4)}, "."))
					
					elseif tag_name == "TAG_FILESIZE" then	
						io.stdout:write(tag_name, ":\t", tag_value)
						
						local index = 1
						local mul = {"B", "KB", "MB", "GB", "TB"}
						while tag_value > 1024 do
							tag_value = tag_value >> 10
							index = index + 1
						end
						
						if index == 1 then
							io.stdout:write(" B")
						else
							io.stdout:write(" B (", tag_value, " ", mul[index], ")")
						end
					
					else
						io.stdout:write(tag_name, ":\t", table.concat(tag[3],  ", "))
						
					end
					
					io.stdout:write("\n")
				end
			end
			
			if file_name then
				if not (ed2k_link_only or magnet_link_only) then
					io.stdout:write("FILE_HASH:\t", id_or_hash, "\n")
				end
				
				local uri_name = file_name:gsub("[ &]", {[" "]="%20", ["&"] = "%26"})
				
				if file_size and not (magnet_link_only or tags_only) then
					io.stdout:write(("ed2k://|file|%s|%s|%s|"):format(uri_name, file_size, id_or_hash))
					if aich then
						io.stdout:write("p=", aich, "|")
					end
					io.stdout:write("/\n")
				end
			
				if not (ed2k_link_only or tags_only) then
					io.stdout:write(("magnet:?xt=urn:ed2k:%s"):format(id_or_hash))
					if aich then
						io.stdout:write("&xt=urn:aich:" .. aich)
					end
					if file_size then
						io.stdout:write("&xl=" .. file_size)
					end
					if bitrate then
						io.stdout:write("&br=" .. bitrate)
					end
					if file_name then
						io.stdout:write("&dn=" .. uri_name)
					end
					
					io.stdout:write("\n")
				end
			elseif source then
				if not ed2k_link_only then
					io.stdout:write("SOURCE_ID:\t", id_or_hash, "\n")
				end
				if file_size and not tag_only then
					io.stdout:write(("ed2k://|file|%s|%s|%s|sources,%s|/\n"):format("s", file_size, search_target:tohex(), source))
				end
			end
		end
	end
end

function check_responces(udp_port)
	local have_data = false
	repeat
		local data, ip, port = receive_packet(udp_port)
		if data then
			have_data = true
			local ok, unpacket_packet = pcall(string.unpack, kad2_packet_format, data, 1, true)
			if ok then
				if unpacket_packet[2][1] == KADEMLIA2_RES then
					check_peers(unpacket_packet[2][2][3], udp_port)
				elseif unpacket_packet[2][1] == KADEMLIA2_SEARCH_RES then
					print_results(unpacket_packet[2][2][4])
				end
			end
		end
	until not data
	return have_data
end



function main()
	
	if arg[1] == "ed2k" or arg[1] == "e" then
		table.remove(arg, 1)
		ed2k_link_only = true
	elseif arg[1] == "magnet" or arg[1] == "m" then
		table.remove(arg, 1)
		magnet_link_only = true
	elseif arg[1] == "tags" or arg[1] == "t" then
		table.remove(arg, 1)
		tags_only = true
	end
	
	if arg[1] == "keyword" or arg[1] == "k" then
		local search_word 
		if arg[2] then
			search_word = arg[2]
		else
			-- получаем от ползователя слово которое будем искать
			search_word = io.stdin:read("*l")
		end

		-- получаем хеш от слова
		search_target = reverse_hash(md4(search_word))
		
		-- упаковываем в пакет
		search_packet = kad2_packet_format:pack({
			ED2K_PROTOCOL_KAD,
			KADEMLIA2_SEARCH_KEY_REQ,
			search_target
		})
		
		if #arg == 2 then
			search_packet = search_packet .. "\0"
		elseif #arg == 3 then
			search_packet = search_packet .. "\x00\x80\1"..string.pack("<s2", arg[3])
		end
		
		
	elseif arg[1] == "hash" or arg[1] == "h" then
		if arg[2] then
			search_target = reverse_hash(arg[2]:fromhex())
		else
			search_target = reverse_hash(io.stdin:read("*l"):fromhex())
		end
		
		search_packet = kad2_packet_format:pack({
			ED2K_PROTOCOL_KAD,
			KADEMLIA2_SEARCH_SOURCE_REQ,
			{
				search_target
				, 0
				, 0 -- размер файла оставим 0 так как на результат не влияет
			}
		})
	else
		print [[
kad.lua [tags|t|ed2k|e|magnet|m] keyword <string>
kad.lua [tags|t|ed2k|e|magnet|m] k <string>
kad.lua          [tags|t|ed2k|e] hash <file hash in hex>
kad.lua          [tags|t|ed2k|e] h <file hash in hex>
]]
		return
	end

	-- загружаем список стартовых узлов
	local bootstrap_file = io.open("nodes.dat", "rb")
	local bootstrap_list = string.unpack(bootstrap_list_format, bootstrap_file:read("*a"), 1, true)
	local peers = #bootstrap_list[2] > 0 and bootstrap_list[2] or bootstrap_list[3][3]
	
	-- это не полный пакет find_value
	find_value_packet = kad2_packet_format:pack({
		ED2K_PROTOCOL_KAD,
		{
			KADEMLIA2_REQ,
			{
				KADEMLIA_FIND_VALUE,
				search_target
			}
		}
	})

	local udp_port = socket.udp()
	udp_port:setsockname("0.0.0.0", 12345)
	udp_port:settimeout(0.001)
	
	check_peers(peers, udp_port)
	
	local timer = os.time()
	while os.time() - timer < 3 do
		if check_responces(udp_port) then
			timer = os.time()
		end
	end
end

main()