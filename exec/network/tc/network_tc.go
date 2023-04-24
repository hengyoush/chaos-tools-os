package tc

import (
	"context"
	"fmt"
	"math/bits"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/chaosblade-io/chaosblade-exec-os/exec"
	"github.com/chaosblade-io/chaosblade-spec-go/log"
	"github.com/chaosblade-io/chaosblade-spec-go/spec"
	"github.com/chaosblade-io/chaosblade-spec-go/util"
)

// TcNetworkBin for network delay, loss, duplicate, reorder and corrupt experiments
const TcNetworkBin = "chaos_tcnetwork"

var commFlags = []spec.ExpFlagSpec{
	&spec.ExpFlag{
		Name: "local-port",
		Desc: "Ports for local service. Support for configuring multiple ports, separated by commas or connector representing ranges, for example: 80,8000-8080",
	},
	&spec.ExpFlag{
		Name: "remote-port",
		Desc: "Ports for remote service. Support for configuring multiple ports, separated by commas or connector representing ranges, for example: 80,8000-8080",
	},
	&spec.ExpFlag{
		Name: "exclude-port",
		Desc: "Exclude local ports. Support for configuring multiple ports, separated by commas or connector representing ranges, for example: 22,8000. This flag is invalid when --local-port or --remote-port is specified",
	},
	&spec.ExpFlag{
		Name: "destination-ip",
		Desc: "destination ip. Support for using mask to specify the ip range such as 92.168.1.0/24 or comma separated multiple ips, for example 10.0.0.1,11.0.0.1.",
	},
	&spec.ExpFlag{
		Name:   "ignore-peer-port",
		Desc:   "ignore excluding all ports communicating with this port, generally used when the ss command does not exist",
		NoArgs: true,
	},
	&spec.ExpFlag{
		Name:                  "interface",
		Desc:                  "Network interface, for example, eth0",
		Required:              true,
		RequiredWhenDestroyed: true,
	},
	&spec.ExpFlag{
		Name: "exclude-ip",
		Desc: "Exclude ips. Support for using mask to specify the ip range such as 92.168.1.0/24 or comma separated multiple ips, for example 10.0.0.1,11.0.0.1",
	},
	&spec.ExpFlag{
		Name:   "force",
		Desc:   "Forcibly overwrites the original rules",
		NoArgs: true,
	},
}

const delimiter = ","

func parseIntegerListToRanges(flagName string, flagValue string) ([][]int, error) {
	dedup := make(map[int]interface{})
	commaParts := strings.Split(flagValue, ",")
	for _, part := range commaParts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		if !strings.Contains(value, "-") {
			intValue, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf(spec.ParameterIllegal.Sprintf(flagName, flagValue, err))
			}
			dedup[intValue] = struct{}{}
			continue
		}
		ranges := strings.Split(value, "-")
		if len(ranges) != 2 {
			return nil, fmt.Errorf(spec.ParameterIllegal.Sprintf(flagName, flagValue,
				"Does not conform to the data format, a connector is required"))
		}
		startIndex, err := strconv.Atoi(strings.TrimSpace(ranges[0]))
		if err != nil {
			return nil, fmt.Errorf(spec.ParameterIllegal.Sprintf(flagName, flagValue, err))
		}
		endIndex, err := strconv.Atoi(strings.TrimSpace(ranges[1]))
		if err != nil {
			return nil, fmt.Errorf(spec.ParameterIllegal.Sprintf(flagName, flagValue, err))
		}
		for i := startIndex; i <= endIndex; i++ {
			dedup[i] = struct{}{}
		}
	}
	list := make([]int, len(dedup))
	for k := range dedup {
		list = append(list, k)
	}
	sort.Ints(list)
	ranges := make([][]int, 0)
	for i := 0; i < len(list); {
		s := list[i]
		curRange := []int{s, s}
		j := i + 1
		for ; j < len(list) && list[j] == list[j-1]; j++ {
		}
		curRange[1] = list[j-1]
		ranges = append(ranges, curRange)
	}
	return ranges, nil
}

func startNet(ctx context.Context, netInterface, classRule, localPort, remotePort, excludePort, destIp, excludeIp string, force, ignorePeerPorts bool, cl spec.Channel) *spec.Response {
	var localPortRanges, remotePortRanges, excludePortRanges [][]int
	var err error
	if localPort != "" {
		localPortRanges, err = parseIntegerListToRanges("local-port", localPort)
		if err != nil {
			return spec.ResponseFailWithFlags(spec.ParameterIllegal, "remote-port", remotePort, err)
		}
	}
	if remotePort != "" {
		remotePortRanges, err = parseIntegerListToRanges("remote-port", remotePort)
		if err != nil {
			return spec.ResponseFailWithFlags(spec.ParameterIllegal, "remote-port", remotePort, err)
		}
	}
	if excludePort != "" {
		excludePortRanges, err = parseIntegerListToRanges("exclude-port", excludePort)
		if err != nil {
			return spec.ResponseFailWithFlags(spec.ParameterIllegal, "exclude-port", excludePort, err)
		}
	}

	// check device txqueuelen size, if the size is zero, then set the value to 1000
	response := preHandleTxqueue(ctx, netInterface, cl)
	if !response.Success {
		return response
	}
	ips, err := readServerIps()
	if len(ips) > 0 {
		channelIps := strings.Join(ips, ",")
		if excludeIp != "" {
			excludeIp = fmt.Sprintf("%s,%s", channelIps, excludeIp)
		} else {
			excludeIp = channelIps
		}
	}
	if force {
		stopNet(ctx, netInterface, cl)
	}
	// Only interface flag
	if localPort == "" && remotePort == "" && excludePort == "" && destIp == "" && excludeIp == "" {
		return cl.Run(ctx, "tc", fmt.Sprintf(`qdisc add dev %s root %s`, netInterface, classRule))
	}

	response = addQdiscForDL(cl, ctx, netInterface)

	// only contains excludePort or excludeIP
	if localPort == "" && remotePort == "" && destIp == "" {
		// Add class rule to 1,2,3 band, exclude port and exclude ip are added to 4 band
		args := buildNetemToDefaultBandsArgs(netInterface, classRule)
		excludeFilters := buildExcludeFilterToNewBand(netInterface, excludePortRanges, excludeIp)
		response := cl.Run(ctx, "tc", args+excludeFilters)
		if !response.Success {
			stopNet(ctx, netInterface, cl)
		}
		return response
	}
	destIpRules := getIpRules(destIp)
	excludeIpRules := getIpRules(excludeIp)
	// local port or remote port
	return executeTargetPortAndIpWithExclude(ctx, cl, netInterface, classRule, localPortRanges, remotePortRanges, destIpRules,
		excludePortRanges, excludeIpRules)
}

func buildExcludeFilterToNewBand(netInterface string, excludePortRanges [][]int, excludeIp string) string {
	var args string
	excludeIpRules := getIpRules(excludeIp)
	for _, rule := range excludeIpRules {
		args = fmt.Sprintf(
			`%s && \
			tc filter add dev %s parent 1: prio 4 protocol ip u32 %s flowid 1:4`,
			args, netInterface, rule)
	}
	for _, portRange := range excludePortRanges {
		masks := buildMaskForRange(portRange[0], portRange[1])
		for _, mask := range masks {
			fmt.Printf("%x", 26)
			args = fmt.Sprintf(
				`%s && \
				tc filter add dev %s parent 1: prio 4 protocol ip u32 match ip dport %d %#x flowid 1:4 && \,
				tc filter add dev %s parent 1: prio 4 protocol ip u32 match ip sport %d %#x flowid 1:4`,
				args, netInterface, mask[0], mask[1], netInterface, mask[0], mask[1])
		}
	}
	return args
}

func buildMaskForRange(start, end int) [][]int {
	cur := start
	masks := make([][]int, 0)
	for cur <= end {
		x := (1 << (bits.Len(uint(cur)) - 1)) - 1
		if end < x {
			x = end
		}
		o := 0
		for (cur & (1 << o)) == 0 {
			o++
		}
		mask := ^0
		cnt := 0
		for {
			upper := cur + (1 << cnt) - 1
			if cnt == o && upper <= x {
				break
			}
			if upper > x {
				mask = mask >> 1
				cnt--
				break
			} else {
				mask <<= 1
				cnt++
			}
		}
		masks = append(masks, []int{cur, mask})
		cur = cur + (1 << cnt)
	}
	return masks
}

func buildNetemToDefaultBandsArgs(netInterface, classRule string) string {
	args := fmt.Sprintf(
		`qdisc add dev %s parent 1:1 %s && \
			tc qdisc add dev %s parent 1:2 %s && \
			tc qdisc add dev %s parent 1:3 %s && \
			tc qdisc add dev %s parent 1:4 handle 40: prio`,
		netInterface, classRule, netInterface, classRule, netInterface, classRule, netInterface)
	return args
}

// Reserved for the peer server ips of the command channel
func readServerIps() ([]string, error) {
	ips := make([]string, 0)
	return ips, nil
}

func preHandleTxqueue(ctx context.Context, netInterface string, cl spec.Channel) *spec.Response {
	txFile := fmt.Sprintf("/sys/class/net/%s/tx_queue_len", netInterface)
	isExist := exec.CheckFilepathExists(ctx, cl, txFile)
	if isExist {
		// check the value
		response := cl.Run(ctx, "head", fmt.Sprintf("-1 %s", txFile))
		if response.Success {
			txlen := strings.TrimSpace(response.Result.(string))
			len, err := strconv.Atoi(txlen)
			if err != nil {
				log.Warnf(ctx, "parse %s file err, %v", txFile, err)
			} else {
				if len > 0 {
					return response
				} else {
					log.Infof(ctx, "the tx_queue_len value for %s is %s", netInterface, txlen)
				}
			}
		}
	}
	if cl.IsCommandAvailable(ctx, "ifconfig") {
		// set to 1000 directly
		response := cl.Run(ctx, "ifconfig", fmt.Sprintf("%s txqueuelen 1000", netInterface))
		if !response.Success {
			log.Warnf(ctx, "set txqueuelen for %s err, %s", netInterface, response.Err)
		}
	}
	return spec.ReturnSuccess("success")
}

func getIpRules(targetIp string) []string {
	if targetIp == "" {
		return []string{}
	}
	ipString := strings.TrimSpace(targetIp)
	ips := strings.Split(ipString, delimiter)
	ipRules := make([]string, 0)
	for _, ip := range ips {
		if strings.TrimSpace(ip) == "" {
			continue
		}
		ipRules = append(ipRules, fmt.Sprintf("match ip dst %s", ip))
	}
	return ipRules
}

// executeTargetPortAndIpWithExclude creates class rule in 1:4 queue and add filter to the queue
func executeTargetPortAndIpWithExclude(ctx context.Context, channel spec.Channel,
	netInterface, classRule string, localPortRanges, remotePortRanges [][]int, destIpRules []string, excludePorts [][]int, excludeIpRules []string) *spec.Response {
	log.Debugf(ctx, fmt.Sprintf(`netInterface: %s, classRule: %s, localPort: %v, remotePort: %v`,
		netInterface, classRule, localPortRanges, remotePortRanges))
	args := fmt.Sprintf(`qdisc add dev %s parent 1:4 handle 40: %s`, netInterface, classRule)
	args = buildTargetFilterPortAndIp(localPortRanges, remotePortRanges, destIpRules, excludePorts, excludeIpRules, args, netInterface)
	response := channel.Run(ctx, "tc", args)
	if !response.Success {
		stopNet(ctx, netInterface, channel)
		return response
	}
	return response
}

func buildTargetFilterPortAndIp(localPortRanges, remotePortRanges [][]int, destIpRules []string, excludePortRanges [][]int, excludeIpRules []string, args string, netInterface string) string {
	if len(localPortRanges) > 0 {
		for _, localPortRange := range localPortRanges {
			masks := buildMaskForRange(localPortRange[0], localPortRange[1])
			for _, mask := range masks {
				if len(destIpRules) > 0 {
					for _, ipRule := range destIpRules {
						args = fmt.Sprintf(
							`%s && \
							tc filter add dev %s parent 1: prio 4 protocol ip u32 %s match ip sport %d %#x flowid 1:4`,
							args, netInterface, ipRule, mask[0], mask[1])
					}
				} else {
					args = fmt.Sprintf(
						`%s && \
						tc filter add dev %s parent 1: prio 4 protocol ip u32 match ip sport %d %#x flowid 1:4`,
						args, netInterface, mask[0], mask[1])
				}
			}
		}
	}
	if len(remotePortRanges) > 0 {
		for _, remotePortRange := range remotePortRanges {
			masks := buildMaskForRange(remotePortRange[0], remotePortRange[1])
			for _, mask := range masks {
				if len(destIpRules) > 0 {
					for _, ipRule := range destIpRules {
						args = fmt.Sprintf(
							`%s && \
							tc filter add dev %s parent 1: prio 4 protocol ip u32 %s match ip dport %d %#x flowid 1:4`,
							args, netInterface, ipRule, mask[0], mask[1])
					}
				} else {
					args = fmt.Sprintf(
						`%s && \
						tc filter add dev %s parent 1: prio 4 protocol ip u32 match ip dport %d %#x flowid 1:4`,
						args, netInterface, mask[0], mask[1])
				}
			}
		}
	}
	if len(remotePortRanges) == 0 && len(localPortRanges) == 0 {
		// only destIp
		for _, ipRule := range destIpRules {
			args = fmt.Sprintf(
				`%s && \
				tc filter add dev %s parent 1: prio 4 protocol ip u32 %s flowid 1:4`,
				args, netInterface, ipRule)
		}
	}
	if len(excludeIpRules) > 0 {
		for _, ipRule := range excludeIpRules {
			args = fmt.Sprintf(
				`%s && \
				tc filter add dev %s parent 1: prio 3 protocol ip u32 %s flowid 1:3`,
				args, netInterface, ipRule)
		}
	}
	if len(excludePortRanges) > 0 {
		for _, excludePortRange := range excludePortRanges {
			masks := buildMaskForRange(excludePortRange[0], excludePortRange[1])
			for _, mask := range masks {
				args = fmt.Sprintf(
					`%s && \
					tc filter add dev %s parent 1: prio 3 protocol ip u32 match ip dport %d %#x flowid 1:3 && \
					tc filter add dev %s parent 1: prio 3 protocol ip u32 match ip sport %d %#x flowid 1:3`,
					args, netInterface, mask[0], mask[1], netInterface, mask[0], mask[1])
			}
		}
	}
	return args
}

// addQdiscForDL creates bands for filter
func addQdiscForDL(channel spec.Channel, ctx context.Context, netInterface string) *spec.Response {
	// add tc filter for delay specify port
	return channel.Run(ctx, "tc", fmt.Sprintf(`qdisc add dev %s root handle 1: prio bands 4`, netInterface))
}

// stopNet
func stopNet(ctx context.Context, netInterface string, cl spec.Channel) *spec.Response {
	if os.Getuid() != 0 {
		return spec.ReturnFail(spec.Forbidden, "tc no permission")
	}

	cl.Run(ctx, "tc", fmt.Sprintf(`filter del dev %s parent 1: prio 4`, netInterface))
	// if !resposne.Success {
	// 	return resposne
	// }
	return cl.Run(ctx, "tc", fmt.Sprintf(`qdisc del dev %s root`, netInterface))
}

// getPeerPorts returns all ports communicating with the port
func getPeerPorts(ctx context.Context, port string, cl spec.Channel) ([]string, error) {
	if !cl.IsCommandAvailable(ctx, "ss") {
		return nil, fmt.Errorf(spec.CommandSsNotFound.Msg)
	}
	response := cl.Run(ctx, "ss", fmt.Sprintf("-n sport = %s or dport = %s", port, port))
	if !response.Success {
		return nil, fmt.Errorf(response.Err)
	}
	if util.IsNil(response.Result) {
		return []string{}, nil
	}
	result := response.Result.(string)
	ssMsg := strings.TrimSpace(result)
	if ssMsg == "" {
		return []string{}, nil
	}
	sockets := strings.Split(ssMsg, "\n")
	log.Infof(ctx, "sockets for %s, %v", port, sockets)
	mappingPorts := make([]string, 0)
	for idx, s := range sockets {
		if idx == 0 {
			continue
		}
		fields := strings.Fields(s)
		for _, f := range fields {
			if !strings.Contains(f, ":") {
				continue
			}
			ipPort := strings.Split(f, ":")
			if len(ipPort) != 2 {
				log.Warnf(ctx, "illegal socket address: %s", f)
				continue
			}
			mappingPorts = append(mappingPorts, ipPort[1])
		}
	}
	return mappingPorts, nil
}
