package xact

import (
	"mynewt.apache.org/newt/nmxact/nmp"
	"mynewt.apache.org/newt/nmxact/sesn"
)

type TaskStatCmd struct {
	CmdBase
}

func NewTaskStatCmd() *TaskStatCmd {
	return &TaskStatCmd{}
}

type TaskStatResult struct {
	Rsp *nmp.TaskStatRsp
}

func newTaskStatResult() *TaskStatResult {
	return &TaskStatResult{}
}

func (r *TaskStatResult) Status() int {
	return r.Rsp.Rc
}

func (c *TaskStatCmd) Run(s sesn.Sesn) (Result, error) {
	r := nmp.NewTaskStatReq()

	rsp, err := txReq(s, r.Msg(), &c.CmdBase)
	if err != nil {
		return nil, err
	}
	srsp := rsp.(*nmp.TaskStatRsp)

	res := newTaskStatResult()
	res.Rsp = srsp
	return res, nil
}