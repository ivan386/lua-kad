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
						 KADEMLIA2_REQ               : B c16 ]]--[[c16]]..[[
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


local MAGICVALUE_UDP_SYNC_CLIENT = ("<I4"):pack(0x395F2EC1)

math.randomseed(os.time() + os.clock())
local my_key = string.pack("<L", math.random(1 << 32 - 1))

function send_packet(data, receiver_id, sender_key, ip, port, socket)
	-- У первого байта первые два бита это тип ключа.
	-- В случае использования в качестве ключа ID узла значение этих бит равно 0.
	
	local first_byte = math.random(0, 255) & (255 << 2)
	
	-- Необходимо проверить что значение этого байта не совпадает с идентификаторами протокола
	-- На самом деле проверок должно быть больше. Может я и переделаю эту часть.
	
	while first_byte == ED2K_PROTOCOL_KAD do
		first_byte = math.random(0, 255) & (255 << 2)
	end
	
	-- Генерируем два случайных байта. Они участвуют в генерации ключа пакета.
	local two_random_bytes = string.pack("<I2", math.random(1<<16 - 1))  
	
	-- Дополняем данные которые будем шифровать дополнительными значениями.
	-- Эти значения позволяют проверить что пакет рашифрован правильно.
	-- А так же мы передаём здесь свой ключь.

	--     magic_value(<I4)              padding(B)    
	data = MAGICVALUE_UDP_SYNC_CLIENT .. "\0"
	--        мы не знаем ключь получателя(receiver_key) поэтому заполняем его нулями
	--        receiver_key(<I4)   sender_key(<I4)
		   .. "\0\0\0\0"        ..sender_key      
		   ..data
	
	-- шифруем
	-- в данном случае для шифрования мы используем ID получателя
	-- мы соеденяем ID и два случайных байта и md5 от этой строки будет ключём шифрования пакета
	data = rc4(md5(receiver_id..two_random_bytes), data)
	
	-- дополняем шифрованный пакет необходимыми для расшифрофки данными
	-- first_byte - позволяет предположить что это шифрованный пакет
	-- two_random_bytes - используются для генерации ключа и расшифровки
	data = string.char(first_byte)..two_random_bytes..data
	
	-- отправляем
	socket:sendto(data, ip, port)
end


function receive_packet(socket)
	local data, ip, port = socket:receivefrom()
	-- 1. Проверяем что мы что то получили
	-- 2. Проверяем что данных достаточно для расшифровки (открытый заголовок + шифрованный заголовок + минимум 2 байта данных)
	-- 3. Проверяем тип шифрования. В нашем случае это только шифрование с использованием ключа то есть значение 2.
	if data and #data > 3 + 4 + 1 + 4 + 4 + 2 and data:byte() & 3 == 2 then
		
		-- расшифровываем
		-- конкатенируем свой ключь и два байта(случайных) со второй позиции
		-- md5 от этого сочетания это ключь пакета
		-- с 4 байта в data идут зашифрованные данные
		local edata = rc4(md5(my_key..data:sub(2,3)), data, 4)
		
		-- проверяем
		-- первым в расшифрованных данных должен быть MAGICVALUE_UDP_SYNC_CLIENT
		local magic_value, next_pos = ("c4"):unpack(edata)
		if magic_value == MAGICVALUE_UDP_SYNC_CLIENT then
			-- далее идет отступ(padding) который нас не интересует и обычно занимает один байт в UDP пакете
			-- потом идет receiver_key 
			_, receiver_key, next_pos = ("s1 c4"):unpack(edata, next_pos)
			
			-- receiver_key должен быть равен нашему ключу который участвовал в генерации ключа пакета
			if receiver_key == my_key then
				-- если всё правльно то записываем в data расшифрованный пакет
				data = edata:sub(next_pos + 4)
			end
		end
	end
	
	-- на этом этапе у нас либо рашифрованный пакет либо не известные данные

	-- проверяем идентификатор протокола в первом байте
	
	if data and data:byte() == ED2K_PROTOCOL_KAD then
		-- это не сжатый пакет
		return data, ip, port
	end

	if data and data:byte() == ED2K_PROTOCOL_KAD_PACKED then 
		-- это сжатый пакет
		
		-- разжимаем
		-- сжатые данные начинаются с 3 позиции
		local cdata, err = deflate:DecompressZlib(data:sub(3))
		if cdata then
			-- меняем идентификатор протокола на не сжатый
			-- на второй позиции находится не сжатый код операции
			-- копируем код операции перед разжатыми данными
			return string.char(ED2K_PROTOCOL_KAD, data:byte(2))..cdata, ip, port
		end
	end	
end

function unpack_ip(data)
	if type(data) == "string" then
		return ("%u.%u.%u.%u"):format(data:reverse():byte(1,4))
		
	elseif type(data) == "number" then
		return ("%u.%u.%u.%u"):format(data & 255, data >> 8 & 255, data >> 16 & 255, data >> 24 & 255)
	end
end

function reverse_hash(hash)
	return string.pack("<LLLL", string.unpack(">LLLL", hash))
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
		
		local   hash_or_id  -- если запрос был на поиск файла то здесь его хеш
                            -- если запрос был на поиск источников то здесь id источника 
			  , tag_count   -- количество тегов
			  , tags        -- теги с информацией о файла либо источнике
			  = table.unpack(result)
		
		if not printed[hash_or_id] then
			printed[hash_or_id] = true
			
			hash_or_id = reverse_hash(hash_or_id):tohex()
			local source_ip, source_port, aich, file_name, file_size, bitrate
			
			if not (ed2k_link_only or magnet_link_only) then
				io.stdout:write("\n")
			end
			
			for _, tag in ipairs(tags) do
			
				local tag_type,       -- здесь идентификатор фомата тега
					  tag_name,       -- имя тега обычно строка в один байт
					  tag_value_table -- это таблица из которой мы возьмём значение 
					  = table.unpack(tag)
				
				local tag_value = tag_value_table[1] -- обычно в таблице одно значение
				
				if TAGS[tag_name] then        -- если есть полное имя для тега
					tag_name = TAGS[tag_name] -- даём более информативное имя тегу
				end
			
				-- заполним переменные для магнита или ed2k ссылки
				if tag_name == "TAG_FILENAME" then
					file_name = tag_value            -- имя файла
					
				elseif tag_name == "TAG_FILESIZE" then
					file_size = tag_value            -- размер файла
					
				elseif tag_name == "TAG_MEDIA_BITRATE" then
					bitrate = tag_value * 1024       -- битрейт в теге указан в килобитах
					
				elseif tag_name == "TAG_SOURCEIP" then
					source_ip = unpack_ip(tag_value) -- распаковываем ip из числа в строку
					
				elseif tag_name == "TAG_SOURCEPORT" then
					source_port = tag_value          -- tcp порт источника
					
				elseif tag_name == "TAG_KADAICHHASHRESULT" then
					-- проверим что данных достаточно для чтения
					if #tag_value >= 22 then
						-- в данном случае мы читаем только первый aich хеш а остальные пропускаем
						local aich_count, aich_sources, aich_hash = ("B B c20"):unpack(tag_value)
						if aich_hash then
							aich = aich_hash:tob32() -- записываем хеш
						end
					end
				end
				
				if not (ed2k_link_only or magnet_link_only) then
					print_tag(tag_name, tag_value, tag_value_table)
				end
			end
			
			if file_name then
				if not (ed2k_link_only or magnet_link_only) then
					io.stdout:write("FILE_HASH:\t", hash_or_id, "\n")
				end
				
				local uri_name = file_name:gsub("[ &|]", {[" "]="%20", ["&"] = "%26", ["|"] = "%7C"})
				
				if file_size and not (magnet_link_only or tags_only) then
					print_ed2k(hash_or_id, aich, file_size, uri_name, source_ip, source_port)
				end
			
				if not (ed2k_link_only or tags_only) then
					print_magnet(hash_or_id, aich, file_size, uri_name)
				end
			elseif source_ip and source_port then
				if not ed2k_link_only then
					io.stdout:write("SOURCE_ID:\t", hash_or_id, "\n")
				end
				if file_size and not tag_only then
					print_ed2k(reverse_hash(search_target):tohex(), nil, file_size, "s", source_ip, source_port)
				end
			end
		end
	end
end

function print_ed2k(hash, aich, file_size, uri_name, source_ip, source_port)
	io.stdout:write(("ed2k://|file|%s|%s|%s|"):format(uri_name, file_size, hash))
	if aich then
		io.stdout:write("p=", aich, "|")
	end
	if source_ip and source_port then
		io.stdout:write("sources,", source_ip, ":", source_port, "|")
	end
	io.stdout:write("/\n")
end

function print_magnet(hash, aich, file_size, uri_name)
	io.stdout:write(("magnet:?xt=urn:ed2k:%s"):format(hash))
	if aich then
		io.stdout:write("&xt=urn:aich:" .. aich)
	end
	if file_size then
		io.stdout:write("&xl=" .. file_size)
	end
	if bitrate then
		io.stdout:write("&br=" .. bitrate)
	end
	if uri_name then
		io.stdout:write("&dn=" .. uri_name)
	end
	
	io.stdout:write("\n")
end

function shift_value(value)
	local count = 0
		
	while value >= 1024 do
		value = value >> 10
		count = count + 1
	end
	
	return count, value
end

function print_tag(tag_name, tag_value, tag_value_table)
	
	if tag_name == "TAG_KADAICHHASHRESULT" then
		-- для начала проверим что данных достаточно для чтения
		if #tag_value >= 22 and #tag_value == 1 + tag_value:byte() * 21 then
			
			-- теперь читаем aich хеши но обычно он один
			local aich_count, aich_list = table.unpack(("[B]{B c20}"):unpack(tag_value, 1, true), nil)
			
			-- выводим имя тега и количество хешей
			io.stdout:write(tag_name, ":\t", aich_count)
			
			for _, aich_info in ipairs(aich_list) do
				local   source_count -- количество источников которые задали этот хеш
					  , aich         -- aich хеш файла
					  = table.unpack(aich_info)
					  
				-- выводим количество источников и сам хеш
				io.stdout:write("\n\t\t", source_count,  ", ", aich:tob32())
			end
		end
		
	elseif tag_name == "TAG_MEDIA_BITRATE" then
		-- выводим битрейт
		io.stdout:write(tag_name, ":\t", tag_value)
		
		-- делаем удодобочитаемый вариант
		local shift_count, value = shift_value(tag_value)
		
		if shift_count == 0 then
			io.stdout:write(" Kb/s")
		else
			-- пишем удодобочитаемый вариант в скобках
			local mul = {"Mb/s", "Gb/s", "Tb/s"}
			io.stdout:write(" Kb/s (", value, " ", mul[shift_count], ")")
		end
	
	elseif tag_name == "TAG_MEDIA_LENGTH" then
		io.stdout:write(  tag_name, ":\t"
						, math.floor(tag_value / 60^2)    , ":" -- часы
						, math.floor(tag_value / 60) % 60 , ":" -- минуты
						, tag_value % 60)                       -- секунды
		
	elseif tag_name == "TAG_PUBLISHINFO" then
		io.stdout:write(  tag_name, ":\t"
						, tag_value >> 24 & 255,      "(name count), " -- количество вариантов имен файла
						, tag_value >> 16 & 255,      "(publishers), " -- количество источников
						, (tag_value & 0xFFFF) / 100, "(trustvalue)" ) -- уровень доверия
		
	elseif tag_name == "TAG_SOURCEIP" or tag_name == "TAG_SERVERIP" then	
		io.stdout:write(tag_name, ":\t", unpack_ip(tag_value)) -- IP источника или ED2K сервера
	
	elseif tag_name == "TAG_FILESIZE" then	
		io.stdout:write(tag_name, ":\t", tag_value) -- точный размер файла
		
		-- делаем удодобочитаемый вариант
		local shift_count, value = shift_value(tag_value)
		
		if shift_count == 0 then
			io.stdout:write(" B")
		else
			-- пишем удодобочитаемый вариант в скобках
			local mul = {"KB", "MB", "GB", "TB"}
			io.stdout:write(" B (", value, " ", mul[shift_count], ")")
		end
	
	else
		io.stdout:write(tag_name, ":\t", table.concat(tag_value_table,  ", "))
		
	end
	
	io.stdout:write("\n")
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
		
		-- https://github.com/amule-project/amule/blob/c0c28234a40b1b575ce51cdfe5ffa5dac3a7494c/src/kademlia/kademlia/Search.cpp#L495
		-- пакет поиска фалов по ключевому слову
		search_packet = kad2_packet_format:pack({
			ED2K_PROTOCOL_KAD,
			{
				KADEMLIA2_SEARCH_KEY_REQ,
				{
					search_target       -- хеш слова по которому будет поиск
				--	, search_terms_flag -- флаг наличия дополнительных параметров поиска (пишем вручную)
				--  , search_terms		-- дополнительные параметры поиска (пишем вручную)
				}
			}
		})
		
		if #arg <= 2 then
			search_packet = search_packet .. "\0\0"
		elseif #arg == 3 then
			search_packet = search_packet .. "\x00\x80\1"..string.pack("<s2", arg[3])
		end
		
		
	elseif arg[1] == "hash" or arg[1] == "h" then
		if arg[2] then
			search_target = reverse_hash(arg[2]:fromhex())
		else
			search_target = reverse_hash(io.stdin:read("*l"):fromhex())
		end
		
		-- https://github.com/amule-project/amule/blob/c0c28234a40b1b575ce51cdfe5ffa5dac3a7494c/src/kademlia/kademlia/Search.cpp#L462
		-- пакет поиска источника файла
		search_packet = kad2_packet_format:pack({
			ED2K_PROTOCOL_KAD,
			{
				KADEMLIA2_SEARCH_SOURCE_REQ,
				{
					search_target
					, 0            -- Start position range (0x0 to 0x7FFF) (не знаю что это)
					, 0            -- размер файла. Оставим 0 так как на результат не влияет.
				}
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
	
	-- https://github.com/amule-project/amule/blob/c0c28234a40b1b575ce51cdfe5ffa5dac3a7494c/src/kademlia/routing/RoutingZone.cpp#L135
	-- формат файла списка узлов
	local bootstrap_list_format = [[
		(*[<L]{< c16 c4 H H B})
		{
			0:
				(<L)
				{
					  [<L] {< c16 c4 H H B         }
					, [<L] {< c16 c4 H H B c4 c4 B }
					, (<L) {[<L] {< c16 c4 H H B } }
				}
		}
	]]

	-- загружаем список стартовых узлов
	local bootstrap_file = io.open("nodes.dat", "rb")
	local bootstrap_list = string.unpack(bootstrap_list_format, bootstrap_file:read("*a"), 1, true)
	local peers =    bootstrap_list[1] > 0     and bootstrap_list[2]          -- список узлов версия 0
	              or bootstrap_list[3][1] == 3 and bootstrap_list[3][2][2][2] -- список узлов версия 3 (большой загрузочный список)
				  or bootstrap_list[3][2][2]                                  -- список узлов версия 1 и 2
	
	-- https://github.com/amule-project/amule/blob/c0c28234a40b1b575ce51cdfe5ffa5dac3a7494c/src/kademlia/kademlia/Search.cpp#L1088
	-- пакет поиска ближайших узлов
	find_value_packet = kad2_packet_format:pack({
		ED2K_PROTOCOL_KAD, -- не сжатый пакет KAD
		{
			KADEMLIA2_REQ, -- поиск узлов
			{
				KADEMLIA_FIND_VALUE -- это на самом деле число ближних к search_target узлов которое мы запрашиваем
				, search_target		-- хеш цели(хеш слова или файла или id узла) для которой мы ищем ближайшие DHT узлы
			--  , node_id           -- id узла к которому обращаемся будет добавлен перед отправкой
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