from pathlib import Path
from bitstring import BitStream, BitArray

def main():
    path = 'Paquetes\ethernet_ipv4_udp_dns.bin'
    print("Archivo: ",path)
    a = BitArray(Path(path).read_bytes())
    printProtocolHeader("Ethernet")
    print("Dirección destino: ",getMAC(a[:48].hex))
    print("Dirección origen: ",getMAC(a[48:96].hex))
    protocol = getProtocol(a[96:112].hex)
    print("Tipo protocolo: ",protocol)
    switcher = {
        "IPv4":IPv4,
        "ARP":ARP,
        "IPv6":IPv6
    }
    func = switcher.get(protocol,"ERROR")
    func(a)

def changePos(pos,value):
    return pos + value
def getMAC(value):
    value = value[:] if len(value) % 2 == 0 else "0" + value[2:]
    return ":".join(value[i:i+2] for i in range(0, len(value), 2))

def formatMSG(data):
    start = 0
    stop = 32
    msg = ""
    while True:
        for i in range(start,stop,2):
            if(len(data) > i):
                msg += data[i] + data[i+1] + " "
            else:
                break
        msg += '\n '
        start = stop
        stop = stop + 32
        if(len(data) < start):
            break
    return msg


def getProtocol(data):
    protocol = {
        "0800": "IPv4",
        "0806": "ARP",
        "8035": "RARP",
        "86dd": "IPv6"
    }
    return protocol.get(data,"ERROR")

def getVersion(data):
    protocol = {
        "0100": "IPv4",
        "0110": "IPv6"
    }
    return protocol.get(data,"ERROR")

def serviceType(data):
    service = {
        "000": "De rutina",
        "001": "Prioritario",
        "010": "Inmediato",
        "011": "Relámpago",
        "100": "Invalidación relámpago",
        "101": "Procesando llamada crítica y de emergencia",
        "110": "Control de trabajo de internet",
        "111": "Control de red"
    }
    print("Prioridad: ",service.get(data[:3].bin,"ERROR"))
    print("Retardo: ","bajo" if data[3] else "normal")
    print("Rendimiento: ","alto" if data[4] else "normal")
    print("Fiabilidad: ","alta" if data[5] else "normal")

def getFlags(data):
    print("Banderas")
    print("--------------------")
    if(data[0]):
        print("ERROR")
    print("No divisible" if data[1] else "Divisible")
    print("Fragmento intermedio" if data[2] else "último fragmento")
    print("--------------------")

def getProtocolIPv4(data):
    protocol = {
        1: "ICMPv4",
        6: "TCP",
        17: "UDP",
        58: "ICMPv6",
        118: "STP",
        121: "SMP"
    }
    return protocol.get(data,"ERROR")

def convertToIp(data):
    IP = []
    data = BitArray(data)
    i = 0
    while(i < len(data)):
        IP.append(data[i:i+8].bin)
        i = i + 8
    address = ""
    for item in IP:
        address += str(int(item,2)) + "."
    address = address[:-1]
    return address

def getClassIPv4(data):
    Class = {
        0: "Control",
        1: "Reservado",
        2: "Depuración y medición",
        3: "Reservado"
    }
    return Class.get(data,"ERROR")

def getNumberIPv4(data):
    number = {
        0: "Final de la lista",
        1: "No operation",
        2: "Security",
        3: "Loose source routing",
        4: "Internet time stamp",
        7: "Record route",
        9: "Strict source routing"
    }
    return number.get(data,"ERROR")

def printProtocolHeader(protocol):
    print("--------------------")
    print(protocol)
    print("--------------------")

def IPv4(data):
    printProtocolHeader("IPv4")
    print("Versión: ",getVersion(data[112:116].bin))
    print("Tamaño de cabecera: ", data[116:120].int * 32, " bits")

    serviceType(data[120:128])

    print("Longitud total: ", data[128:144].int * 32, "---", (data[128:144].int * 32) / 8, " bytes" )
    print("Identificador: ",data[144:160].int * 32)

    getFlags(data[160:163])

    print("Posición de fragmento: ",data[163:176].int)
    print("TTL: ",data[176:184].int)

    protocol = getProtocolIPv4(data[184:192].int)

    print("Protocolo: ",protocol)
    print("Suma de control: ",data[192:208].hex)

    print("IP origen: ", convertToIp(data[208:240]))
    print("IP destino: ", convertToIp(data[240:272]))

    ProtocolType = {
        "ICMPv4":ICMPv4,
        "TCP":TCP,
        "UDP": UDP
    }
    func = ProtocolType.get(protocol,"ERROR")
    func(data,272)

def TypeICMPv4(data):
    switcher = {
        0:"'Echo Reply'",
        3:"'Destination Unreachable'",
        4:"'Source Quench'",
        5:"'Redirect'",
        8:"'Echo'",
        11:"'Time exceeded'",
        12:"'Parameter problem'",
        13:"'Timespamp'",
        14:"'Timestamp reply'",
        16:"'Information reply'",
        17:"'Addressmask'",
        18:"'Adrdressmask reply'"
    }
    return switcher.get(data,"ERROR")

def CodeICMPv4(data):
    switcher = {
        0:"'No se puede llegar a la red'",
        1:"'No se puede llegar al host o aplicación destino'",
        2:"'El destino no dispone del protocolo solicitado'",
        3:"'No se puede llegar al puerto destino o la aplicación no está libre'",
        4:"'Se necesita aplicar fragmentación pero la bandera correspondiente indica lo contrario'",
        5:"'La ruta de origen no es correcta'",
        6:"'No se reconoce la red destino'",
        7:"'No se reconoce el host destino'",
        8:"'El host origen está aislado'",
        9:"'la comunicación con al red destino está prohibida por razones administrativas'",
        10:"'la comunicación con el host destino está prohibida por razones administrativas'",
        11:"'No se puede llegar a la red destino debido al tipo de servicio'",
        12:"'No se puede llegar al host destino debido al tipo de servicio'"
    }
    return switcher.get(data,"ERROR")

def ICMPv4(data,pos):
    printProtocolHeader("ICMPv4")
    print("Tipo: ",data[272:280].int,"\n",TypeICMPv4(data[272:280].int))
    print("Código: ",data[280:288].int,"\n",CodeICMPv4(data[280:288].int))
    print("Suma de control: ",data[288:304].hex)
    print("Data: \n",formatMSG(data[304:].hex))

def getHardwareType(data):
    hw = {
        0: "Reserved",
        1: "Ethernet (10Mb)",
        6: "IEEE 802 networks",
        7: "ARCNET",
        15: "Frame relay",
        16: "Asyncronous transmission mode",
        17: "HDLC",
        18: "Fibre channel",
        19: "Asyncronous transmission mode",
        20: "Serial line"
    }
    return hw.get(data,"Unassigned")

def getOPCode(data):
    hw = {
        1: "ARP request",
        2: "ARP reply",
        3: "RARP request",
        4: "RARP reply",
        5: "DRARP request",
        6: "DRARP reply",
        7: "DRARP error",
        8: "InARP request",
        9: "InARP reply"
    }
    return hw.get(data,"Unassigned")

def ARP(data):
    printProtocolHeader("ARP")
    print("Tipo de hardware: ",getHardwareType(data[112:128].int))
    print("Tipo de protocolo: ",getProtocol(data[128:144].hex))

    hwLenght = data[144:152].int * 8
    protocolLenght = data[152:160].int * 8

    OPCode = getOPCode(data[160:176].int)

    print("Código de operación: ",OPCode)
    actualByte = 176

    print("Dirección MAC del emisor: ", getMAC(data[actualByte:actualByte + hwLenght].hex))
    actualByte = actualByte + hwLenght
    print("Dirección IP del emisor: ", convertToIp(data[actualByte: actualByte + protocolLenght]))
    actualByte = actualByte + protocolLenght
    print("Dirección MAC del receptor: ", getMAC(data[actualByte:actualByte + hwLenght].hex))
    actualByte = actualByte + hwLenght
    print("Dirección IP del receptor: ", convertToIp(data[actualByte: actualByte + protocolLenght]))
    actualByte = actualByte + protocolLenght
    print("Mensaje:\n",formatMSG(data[actualByte:].hex))

def addressIPv6(data):
    return ':'.join(data[i:i+4] for i in range(0, len(data), 4))

def IPv6(data):
    printProtocolHeader("IPv6")
    print("Versión: ",data[112:116].uint )

    serviceType(data[116:124])

    print("Etiqueta de flujo: ",data[124:144].uint )
    print("Tamaño de datos: ",data[144:160].uint )

    protocol = getProtocolIPv4(data[160:168].uint )
    
    print("Encabezado siguiente: ",protocol)
    print("Limite de salto: ",data[168:176].uint )
    print("Dirección de origen: ",addressIPv6(data[176:304].hex))
    print("Dirección de destino: ",addressIPv6(data[304:432].hex))
    switcher = {
        "ICMPv6":ICMPv6,
        "TCP":TCP,
        "UDP":UDP
    }
    func = switcher.get(protocol,"ERROR")
    func(data,432)

def TypeICMPv6(data):
    codeList = {
        1: "Mensaje de destino inalcanzable",
        2: "Mensaje de paquete demasiado grande",
        3: "Time exceeded Message",
        4: "Mensaje de problema de parámetro",
        128: "Mensaje del pedido de eco",
        129: "Mensaje de respuesta de eco",
        133: "Mensaje de solicitud del router",
        134: "Mensaje de anuncio del router",
        135: "Mensaje de solicitud vecino",
        136: "Mensaje de anuncio vecino",
        137: "Reoriente el mensaje"
    }
    return codeList.get(data,"Unassigned")

def CodeICMPv6(data,_type):
    if(_type == 1 ):
        codeList = {
            0: "No existe ruta destino",
            1: "Comunicación con el destino administrativamente prohibida",
            2: "No asignado",
            3: "Dirección inalcanzable"
        }
    elif _type == 2:
        return " "
    elif _type == 3:
        codeList = {
        0: "Límite de salto excedido",
        1: "Tiempo de reemsamble de fragmento excedido"
    }
    elif _type == 4:
        codeList = {
        0: "Campo del encabezado erroneo",
        1: "Tipo siguiente desconocido",
        2: "Opción desconocida de IPv6"
    }
    else:
        return " "
    return codeList.get(data,"Unassigned")

def ICMPv6(data,pos):
    printProtocolHeader("ICMPv6")
    _type = data[432:440].uint
    code = data[440:448].int
    print("Tipo: ",_type," \n",TypeICMPv6(_type))
    print("Código: ",code," \n",CodeICMPv6(code,_type))
    print("Suma de comprobación: ",data[448:464].hex)
    print("Contenido: \n",formatMSG(data[464:].hex))

def getTCPPort(data):
    if(1024 <= data <= 49151):
        return "Puerto registrado"
    elif(49152 <= data <= 65535):
        return "Puerto dinamico o privado"
    codeList = {
        20: "FTP",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        69: "TFTP",
        80: "HTPP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        993: "IMAP SSL",
        995: "POP SSL"
    }
    return "Puerto bien conocido "+ codeList.get(data,"")

def getTCPFlags(data):
    print("NS: ",data[0],"| CWR: ",data[1],"| ECE: ",data[2],"| URG: ",data[3])
    print("ACK: ",data[4],"| PSH: ",data[5],"| RST: ",data[6],"| SYN: ",data[7],"| FIN: ",data[8])

def TCP(data,pos):
    printProtocolHeader("TCP")
    port = data[pos:pos+16].uint
    print("Puerto origen: ",port," ",getTCPPort(port))
    pos = changePos(pos,16)
    port = data[pos:pos+16].uint
    print("Puerto destino: ",port," ",getTCPPort(port))
    pos = changePos(pos,16)
    print("Numero de secuencia: ",data[pos:pos+32].uint)
    pos = changePos(pos,32)
    print("Numero de acuse de recibo: ",data[pos:pos+32].uint)
    pos = changePos(pos,32)
    print("Longitud de cabecera: ",data[pos:pos + 4].uint)
    pos = changePos(pos,4)
    print("Reservado: ",data[pos:pos + 3].bin)
    pos = changePos(pos,3)
    getTCPFlags([int(i) for i in data[pos:pos + 9]])
    pos = changePos(pos,9)
    print("Tamaño de ventana: ",data[pos:pos + 16].uint)
    pos = changePos(pos,16)
    print("Suma de verificación: ",data[pos:pos + 16].hex)
    pos = changePos(pos,16)
    print("Puntero urgente: ",data[pos:pos + 16].uint)
    pos = changePos(pos,16)
    #print("Data: ",formatMSG(data[pos:].hex))
    DNS(data,pos)


def UDP(data,pos):
    printProtocolHeader("UDP")
    print("Puerto de origen: ",getTCPPort(data[pos:pos+16].uint))
    pos = changePos(pos,16)
    print("Puerto de destino: ",getTCPPort(data[pos:pos+16].uint))
    pos = changePos(pos,16)
    print("Longitud total: ",data[pos:pos+16].hex)
    pos = changePos(pos,16)
    print("Suma de comprobación: ", data[pos:pos+16].hex)
    pos = changePos(pos,16)
    #print("Data: ",formatMSG(data[pos:].hex))
    DNS(data,pos)

def FlagsDNS(data,pos):
    if(data[pos:pos+1]):
        print("QR: Consulta")
    else:
        print("QR: Respuesta")
    pos = changePos(pos,1)
    if(data[pos:pos+4].uint == 0):
        print("OP code: QUERY")
    if(data[pos:pos+4].uint == 1):
        print("OP code: IQUERY")
    if(data[pos:pos+4].uint == 2):
        print("OP code: STATUS")
    pos = changePos(pos,4)
    if(data[pos:pos+1]):
        print("AA: Respuesta autorizada")
    else:
        print("AA: Respuesta no autorizada")
    pos = changePos(pos,1)
    if(data[pos:pos+1]):
        print("TC: Truncado")
    else:
        print("TC: No truncado")
    pos = changePos(pos,1)
    if(data[pos:pos+1]):
        print("RD: Recursión deseado")
    else:
        print("RD: Recursión no deseada")
    pos = changePos(pos,1)
    if(data[pos:pos+1]):
        print("RA: Recursión disponible")
    else:
        print("RA: Recursión no disponible")
    pos = changePos(pos,1)
    print("Z: ",data[pos:pos+3].uint)
    pos = changePos(pos,3)
    codeList = {
        0: "Ningún error",
        1: "Error de formato",
        2: "Fallo en el servidor",
        3: "Error en nombre",
        4: "No implementado",
        5: "Rechazado"
    }
    print("Rcode: ",codeList.get(data[pos:pos+4].uint,""))
    pos = changePos(pos,4)
    return pos

def GetDomName(data,pos,opc):
    direction = ""
    while(True):
        number = data[pos:pos+8].uint
        if(number == 0):
            direction = direction[:-1]
            pos = changePos(pos,8)
            break
        pos = changePos(pos,8)
        direction += (bytes.fromhex(data[pos:pos + (8*number)].hex)).decode("ASCII") + "."
        pos = changePos(pos,8*number)
    
    print("Nombre del dominio: ",direction)
    if(opc == 0):
        return pos
    return direction

def DNS(data,pos):
    typeList = {
        1: "A",
        5: "CNAME",
        13: "HINFO",
        15: "MX",
        22: "NS",
        23: "NS"
    }
    classList = {
        1: "IN",
        5: "CH"
    }
    printProtocolHeader("DNS")
    print("ID: ",data[pos:pos+16].hex)
    pos = changePos(pos,16)
    pos = FlagsDNS(data,pos)
    QDcount = data[pos:pos+16].uint
    print("QDcount: ",QDcount)
    pos = changePos(pos,16)
    ANcount = data[pos:pos+16].uint
    print("ANcount: ",ANcount)
    pos = changePos(pos,16)
    print("NScount: ",data[pos:pos+16].uint)
    pos = changePos(pos,16)
    print("ARcount: ",data[pos:pos+16].uint)
    pos = changePos(pos,16)
    if(QDcount != 0):
        printProtocolHeader("PREGUNTA DNS")
        pos = GetDomName(data,pos,0)
        typeTxt = typeList.get(data[pos:pos+16].uint,"TIPO NO LISTADO")
        print("Tipo: ", typeTxt )
        pos = changePos(pos,16)
        print("Clase: ",classList.get(data[pos:pos+16].uint,"CLASE NO LISTADADA"))
        pos = changePos(pos,16)
    if(ANcount != 0):
        printProtocolHeader("RESPUESTA DNS")
        domName = GetDomName(data,data[pos:pos + 16].uint,1)
        pos = changePos(pos,16)
        print("Tipo: ",typeList.get(data[pos:pos+16].uint,"TIPO NO LISTADO"))
        pos = changePos(pos,16)
        print("Clase: ",classList.get(data[pos:pos+16].uint,"CLASE NO LISTADADA"))
        pos = changePos(pos,16)
        print("TTL: ",data[pos:pos + 32].uint," segundos")
        pos = changePos(pos,32)
        datalenght = data[pos:pos + 16].uint
        pos = changePos(pos,16)
        print("Longitud de datos: ",datalenght)
        if(typeTxt == "A"):
            print("IP: ",convertToIp(data[pos:pos + datalenght]))
        elif(typeTxt == "CNAME"):
            print("Dom name: ",domName)
        elif(typeTxt == "MX"):
            print("Prioridad: ",data[pos:pos + 16].uint)
            pos = changePos(pos,16)
            print("Nombre del ordenador: ", (bytes.fromhex(data[pos:].hex)).decode("ASCII") )
        elif(typeTxt == "NS"):
            print("Nombre del ordenador: ", (bytes.fromhex(data[pos:pos + datalenght].hex)).decode("ASCII") )
        
    print("DATA: ",data[pos:].hex)
    
    #pos = GetDomName(data,pos)

if __name__ == '__main__':
    main()