package gpgcli

import "fmt"

// Run parses argv and executes the requested operation.
func Run(argv []string) error {
	o, err := Parse(argv)
	if err != nil {
		return err
	}

	switch o.Operation {
	case opVersion:
		printVersion()
		return nil
	case opHelp, opNone:
		printHelp()
		return nil

	case opGenKey:
		return cmdGenKey(o)
	case opQuickGenKey:
		return cmdQuickGenKey(o)

	case opListPublic:
		return cmdListKeys(o, false)
	case opListSecret:
		return cmdListKeys(o, true)

	case opExport:
		return cmdExport(o, false)
	case opExportSecret:
		return cmdExport(o, true)
	case opImport:
		return cmdImport(o)

	case opDeleteKey:
		return cmdDeleteKey(o, true, false)
	case opDeleteSecret:
		return cmdDeleteKey(o, false, true)
	case opDeleteBoth:
		return cmdDeleteKey(o, true, true)

	case opEncrypt:
		return cmdEncrypt(o)
	case opSign:
		return cmdSign(o)
	case opDetachSign:
		return cmdDetachSign(o)
	case opClearSign:
		return cmdClearSign(o)
	case opSymmetric:
		return cmdSymmetric(o)
	case opDecrypt:
		return cmdDecrypt(o)
	case opVerify:
		return cmdVerify(o)

	case opListPackets:
		return cmdListPackets(o)

	default:
		return fmt.Errorf("unhandled operation: %s", o.Operation)
	}
}
