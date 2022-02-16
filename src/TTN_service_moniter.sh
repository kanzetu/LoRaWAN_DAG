#/bin/bash
awkcmd='
function info(s){
	print " " TX_WH BK_GN "INFO" BK_RST TX_RST "\t" s
}

function warning(s){
        print " " TX_WH BK_YL "WARN" BK_RST TX_RST "\t" s
}

function error(s){
        print " " TX_WH BK_RD "ERRO" BK_RST TX_RST "\t" s
}

function stat(s){
        print " " TX_WH BK_CY "STAT" BK_RST TX_RST "\t" s
}

function uplink(s){
	return TX_WH BK_BL " UPLINK " BK_RST TX_RST " " s
}

function downlink(s){
        return TX_WH BK_PL "DOWNLINK" BK_RST TX_RST " " s
}


BEGIN {
	BK_RST = "\033[0m"
	BK_RD = "\033[41;4m"
	BK_GN = "\033[42;4m"
	BK_YL = "\033[43;4m"
	BK_BL = "\033[44;1m"
	BK_PL = "\033[45;1m"
	BK_CY = "\033[46;4m"
	TX_WH = "\033[37;1m"
	TX_RST = "\033[0m"
	info("Start monitering service : ttn-gateway...")
}

{
	#print $7
	s = ""; for (i = 6; i <= NF; i++) s = s $i " "
	if ($7 == "up:")
		info($2 "/" $1 " " $3 " " uplink(s))
	else if ($7 == "down:")
                info($2 "/" $1 " " $3 " " downlink(s))
	else if (($6 == "WARNING:") && ($7 == "[down]"))	# Warning downlink
                warning($2 "/" $1 " " $3 " " downlink(s))
        else if (($6 == "INFO:") && ($7 == "[down]"))      # Warning downlink
                info($2 "/" $1 " " $3 " " downlink(s))
        else if ($6 == "ERROR:")        # ERROR
                error($2 "/" $1 " " $3 " " downlink(s))
	else if ($7 == "ERROR:")        # ERROR
                error($2 "/" $1 " " $3 " " downlink(s))
        else if (index($6, "#") != 0){
                stat($2 "/" $1 " " $3 " " s)
        }else if ($6 == "INFO:"){
		s = ""; for (i = 7; i <= NF; i++) s = s $i " "
                info($2 "/" $1 " " $3 " " downlink(s))
	}else
		info($2 "/" $1 " " $3 " " s)
	}
'

journalctl -xf | grep ttn-gateway | awk "$awkcmd"
