package fingerprint

import "regexp"

// port fingerprint def
// ref https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes

// Available variables: {PORT},{IP}

var serviceOrder = []string{"http", "https", "ssh", "redis", "mysql"}

var onlyRecv []string

// 一组数据流，仅一次发送
var groupFlows = map[string][]string{
	"http": {"redis", "memcached"},
}

var portServiceOrder = map[uint16][]string{
	21:    {"ftp"},
	22:    {"ssh"},
	80:    {"http", "https"},
	443:   {"https", "http"},
	445:   {"smb"},
	1035:  {"oracle"},
	1080:  {"socks5", "socks4"},
	1081:  {"socks5", "socks4"},
	1082:  {"socks5", "socks4"},
	1083:  {"socks5", "socks4"},
	1433:  {"sqlserver"},
	1521:  {"oracle"},
	1522:  {"oracle"},
	1525:  {"oracle"},
	1526:  {"oracle"},
	1574:  {"oracle"},
	1748:  {"oracle"},
	1754:  {"oracle"},
	3306:  {"mysql"},
	3389:  {"ms-wbt-server"},
	6379:  {"redis"},
	9001:  {"mongodb"},
	11211: {"memcached"},
	14238: {"oracle"},
	27017: {"mongodb"},
	20000: {"oracle"},
	49153: {"mongodb"},
}

func init() {
	// http
	serviceRules["http"] = serviceRule{
		Tls: false,
		DataGroup: []ruleData{
			{
				ActionSend,
				[]byte("HEAD / HTTP/1.1\r\nHost: {IP}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: deflate\r\n\r\n"),
				nil,
			},
			{
				ActionRecv,
				[]byte("HTTP/"),
				nil,
			},
		},
	}
	// https
	serviceRules["https"] = serviceRule{
		Tls:       true,
		DataGroup: serviceRules["http"].DataGroup,
	}

	// ssh
	serviceRules["ssh"] = serviceRule{
		Tls: false,
		DataGroup: []ruleData{
			{
				ActionRecv,
				nil,
				[]*regexp.Regexp{
					regexp.MustCompile(`^SSH-([\d.]+)-`),
					regexp.MustCompile(`^SSH-(\d[\d.]+)-`),
					regexp.MustCompile(`^SSH-(\d[\d.]*)-`),
					regexp.MustCompile(`^SSH-2\.0-`),
					regexp.MustCompile(`^SSH-1\.`),
				},
			},
		},
	}

	// ftp
	serviceRules["ftp"] = serviceRule{
		Tls: false,
		DataGroup: []ruleData{
			{
				ActionRecv,
				nil,
				[]*regexp.Regexp{
					regexp.MustCompile(`^220 ([-/.+\w]+) FTP server`),
					regexp.MustCompile(`^220[ |-](.*?)FileZilla`),
					regexp.MustCompile(`^(?i)220[ |-](.*?)version`),
					regexp.MustCompile(`^220 3Com `),
					regexp.MustCompile(`^220-GuildFTPd`),
					regexp.MustCompile(`^220-.*\r\n220`),
					regexp.MustCompile(`^220 Internet Rex`),
					regexp.MustCompile(`^530 Connection refused,`),
					regexp.MustCompile(`^220 IIS ([\w._-]+) FTP`),
					regexp.MustCompile(`^220 PizzaSwitch `),
					regexp.MustCompile(`(?i)^220 ([-.+\w]+) FTP`),
					regexp.MustCompile(`(?i)^220[ |-](.*?)FTP`),
				},
			},
		},
	}

	// socks4
	serviceRules["socks4"] = serviceRule{
		Tls: false,
		DataGroup: []ruleData{
			{
				ActionSend,
				[]byte("\x04\x01\x00\x16\x7f\x00\x00\x01rooo\x00"),
				nil,
			},
			{
				ActionRecv,
				nil,
				[]*regexp.Regexp{
					regexp.MustCompile(`^\x00\x5a`),
					regexp.MustCompile(`^\x00\x5b`),
					regexp.MustCompile(`^\x00\x5c`),
					regexp.MustCompile(`^\x00\x5d`),
				},
			},
		},
	}

	// socks5
	serviceRules["socks5"] = serviceRule{
		Tls: false,
		DataGroup: []ruleData{
			{
				ActionSend,
				[]byte("\x05\x04\x00\x01\x02\x80\x05\x01\x00\x03\x0dwww.baidu.com\x00\x50GET / HTTP/1.0\r\n\r\n"),
				nil,
			},
			{
				ActionRecv,
				nil,
				[]*regexp.Regexp{
					regexp.MustCompile(`^\x05\x00\x05\x01`),
					regexp.MustCompile(`^\x05\x00\x05\x00\x00\x01.{6}HTTP`),
					regexp.MustCompile(`^\x05\x02`),
					regexp.MustCompile(`^\x05\x00`),
				},
			},
		},
	}

	//// tls
	//serviceRules["tls"] = serviceRule{
	//	Tls: false,
	//	DataGroup: []ruleData{
	//		{
	//			ActionSend,
	//			[]byte("\x16\x03\x00\x00S\x01\x00\x00O\x03\x00?G\xd7\xf7\xba,\xee\xea\xb2`~\xf3\x00\xfd\x82{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\xdbo\xef\x10n\x00\x00(\x00\x16\x00\x13\x00\x0a\x00f\x00\x05\x00\x04\x00e\x00d\x00c\x00b\x00a\x00`\x00\x15\x00\x12\x00\x09\x00\x14\x00\x11\x00\x08\x00\x06\x00\x03\x01\x00"),
	//			nil,
	//		},
	//		{
	//			ActionRecv,
	//			nil,
	//			[]*regexp.Regexp{
	//				regexp.MustCompile(`^[\x16\x15]\x03\x00`),
	//				regexp.MustCompile(`^[\x16\x15]\x03...\x02`),
	//			},
	//		},
	//	},
	//}

	// smb
	serviceRules["smb"] = serviceRule{
		Tls: false,
		DataGroup: []ruleData{
			{
				ActionSend,
				[]byte("\x00\x00\x00\xa4\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x06\x00\x00\x01\x00\x00\x81\x00\x02PC NETWORK PROGRAM 1.0\x00\x02MICROSOFT NETWORKS 1.03\x00\x02MICROSOFT NETWORKS 3.0\x00\x02LANMAN1.0\x00\x02LM1.2X002\x00\x02Samba\x00\x02NT LM 0.12\x00\x02NT LANMAN 1.0\x00"),
				nil,
			},
			{
				ActionRecv,
				nil,
				[]*regexp.Regexp{
					regexp.MustCompile(`MBr\x00\x00\x00\x00\x88\x01@\x00`),
				},
			},
		},
	}

	// ms-wbt-server
	serviceRules["ms-wbt-server"] = serviceRule{
		Tls: false,
		DataGroup: []ruleData{
			{
				ActionSend,
				[]byte("\x03\x00\x00*%\xe0\x00\x00\x00\x00\x00Cookie: mstshash=pcpc\r\n\x01\x00\x08\x00\x03\x00\x00\x00"),
				nil,
			},
			{
				ActionRecv,
				nil,
				[]*regexp.Regexp{
					regexp.MustCompile(`\x03\x00\x00.\x0e\xd0\x00\x00\x124\x00`),
				},
			},
		},
	}

	// jdwp
	serviceRules["jdwp"] = serviceRule{
		Tls: false,
		DataGroup: []ruleData{
			{
				ActionRecv,
				[]byte("JDWP-Handshake"),
				nil,
			},
		},
	}

	// jdbc
	serviceRules["jdbc"] = serviceRule{
		Tls: false,
		DataGroup: []ruleData{
			{
				ActionRecv,
				[]byte("HSQLDB JDBC Network Listener"),
				nil,
			},
		},
	}

	// ice
	serviceRules["ice"] = serviceRule{
		Tls: false,
		DataGroup: []ruleData{
			{
				ActionRecv,
				[]byte("IceP\x01\x00\x01\x00\x03\x00\x0e\x00\x00\x00"),
				nil,
			},
		},
	}

	// Db
	// mysql
	serviceRules["mysql"] = serviceRule{
		Tls: false,
		DataGroup: []ruleData{
			{
				ActionRecv,
				nil,
				[]*regexp.Regexp{
					regexp.MustCompile(`(?s)^.\x00\x00\x00\xff..Host .* is not allowed to connect to this .* server$`),
					regexp.MustCompile(`^.\x00\x00\x00\xff..Too many connections`),
					regexp.MustCompile(`(?s)^.\x00\x00\x00\xff..Host .* is blocked because of many connection errors`),
					regexp.MustCompile(`(?s)^.\x00\x00\x00\x0a(\d\.[-_~.+:\w]+MariaDB-[-_~.+:\w]+)`),
					regexp.MustCompile(`(?s)^.\x00\x00\x00\x0a(\d\.[-_~.+\w]+)\x00`),
					regexp.MustCompile(`(?s)^.\x00\x00\x00\xffj\x04'[\d.]+' .* MySQL`),
				},
			},
		},
	}
	// redis
	serviceRules["redis"] = serviceRule{
		Tls: false,
		DataGroup: []ruleData{
			{
				ActionSend,
				[]byte("GET / HTTP/1.1\r\n"),
				nil,
			},
			{
				ActionRecv,
				nil,
				[]*regexp.Regexp{
					regexp.MustCompile(`-ERR operation not permitted\r\n`),
					regexp.MustCompile(`-ERR wrong number of arguments for 'get' command\r\n`),
				},
			},
		},
	}

	// sqlserver
	serviceRules["sqlserver"] = serviceRule{
		Tls: false,
		DataGroup: []ruleData{
			{
				ActionSend,
				[]byte("\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00"),
				nil,
			},
			{
				ActionRecv,
				[]byte("\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff"),
				nil,
			},
		},
	}

	// oracle
	serviceRules["oracle"] = serviceRule{
		Tls: false,
		DataGroup: []ruleData{
			{
				ActionSend,
				[]byte("\x00Z\x00\x00\x01\x00\x00\x00\x016\x01,\x00\x00\x08\x00\x7F\xFF\x7F\x08\x00\x00\x00\x01\x00 \x00:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x004\xE6\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00(CONNECT_DATA=(COMMAND=version))"),
				nil,
			},
			{
				ActionRecv,
				nil,
				[]*regexp.Regexp{
					regexp.MustCompile(`(?s)^\x00\x20\x00\x00\x02\x00\x00\x00\x016\x00\x00\x08\x00\x7f\xff\x01\x00\x00\x00\x00\x20`),
					regexp.MustCompile(`^\+\x00\x00\x00$`),
					regexp.MustCompile(`^\x00.\x00\x00\x02\x00\x00\x00.*\(IAGENT`),
					regexp.MustCompile(`^..\x00\x00\x04\x00\x00\x00"\x00..\(DESCRIPTION=`),
					regexp.MustCompile(`^\x00.\x00\x00[\x02\x04]\x00\x00\x00.*\(`),
					regexp.MustCompile(`^\x00.\x00\x00[\x02\x04]\x00\x00\x00.*TNSLSNR`),
					regexp.MustCompile(`^\x00,\x00\x00\x04\x00\x00"`),
				},
			},
		},
	}

	// mongodb
	serviceRules["mongodb"] = serviceRule{
		Tls: false,
		DataGroup: []ruleData{
			{
				ActionSend,
				[]byte("\x41\x00\x00\x00\x3a\x30\x00\x00\xff\xff\xff\xff\xd4\x07\x00\x00\x00\x00\x00\x00test.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x01serverStatus\x00\x00\x00\x00\x00\x00\x00\xf0\x3f\x00"),
				nil,
			},
			{
				ActionRecv,
				nil,
				[]*regexp.Regexp{
					regexp.MustCompile(`(?s)^.*version([: "]+)([.\d]+)"`),
					regexp.MustCompile(`(?s)^\xcb\x00\x00\x00....:0\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\xa7\x00\x00\x00\x01uptime\x00\x00\x00\x00\x00\x00 ` + "`" + `@\x03globalLock\x009\x00\x00\x00\x01totalTime\x00\x00\x00\x00\x7c\xf0\x9a\x9eA\x01lockTime\x00\x00\x00\x00\x00\x00\xac\x9e@\x01ratio\x00!\xc6\$G\xeb\x08\xf0>\x00\x03mem\x00<\x00\x00\x00\x10resident\x00\x03\x00\x00\x00\x10virtual\x00\xa2\x00\x00\x00\x08supported\x00\x01\x12mapped\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01ok\x00\x00\x00\x00\x00\x00\x00\xf0\?\x00$`),
					regexp.MustCompile(`(?s)^.\x00\x00\x00....:0\x00\x00\x01\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\+\x00\x00\x00\x02errmsg\x00\x0e\x00\x00\x00need to login\x00\x01ok\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`),
					regexp.MustCompile(`(?s)^.\x00\x00\x00....:0\x00\x00\x01\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00.\x00\x00\x00\x01ok\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02errmsg\x00.\x00\x00\x00not authorized on`),
				},
			},
		},
	}

	// memcached
	serviceRules["memcached"] = serviceRule{
		Tls: false,
		DataGroup: []ruleData{
			{
				ActionSend,
				[]byte("stats\n"),
				nil,
			},
			{
				ActionRecv,
				nil,
				[]*regexp.Regexp{
					regexp.MustCompile(`(?s)^STAT pid \d`),
					regexp.MustCompile(`(?s)^ERROR\r\n`),
					regexp.MustCompile(`(?s)^SERVER_ERROR `),
				},
			},
		},
	}

	// onlyRecv
	for k, m := range serviceRules {
		if len(m.DataGroup) == 1 {
			onlyRecv = append(onlyRecv, k)
		}
	}
}
