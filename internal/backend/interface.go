package backend

type Rule struct {
    Tags map[string]string
    Chain string
    Table string
    PacketCount uint64
    ByteCount uint64
}

type FirewallBackend interface {
    GetRules() []Rule
}
