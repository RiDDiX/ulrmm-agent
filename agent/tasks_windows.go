// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"git.riddix.de/RiDDiX/ulrmm-agent/internal/taskmaster"
	"github.com/rickb777/date/period"
)

// SchedTask is the schedtaskpayload of a request. The tags and the library
// types are the wire format the server sends (autotasks/models.py).
type SchedTask struct {
	PK          int    `json:"pk"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	RunASAP     bool   `json:"start_when_available"`
	Enabled     bool   `json:"enabled"`
	Overwrite   bool   `json:"overwrite_task"`
	DeleteAfter bool   `json:"delete_expired_task_after"`
	// the command the task runs and how instances overlap
	Path       string                         `json:"path"`
	Args       string                         `json:"args"`
	WorkDir    string                         `json:"workdir"`
	TaskPolicy taskmaster.TaskInstancesPolicy `json:"multiple_instances"`
	// trigger, with the fields of its daily and weekly kinds
	Trigger      string                  `json:"trigger"`
	DayInterval  taskmaster.DayInterval  `json:"day_interval"`
	WeekInterval taskmaster.WeekInterval `json:"week_interval"`
	DaysOfWeek   taskmaster.DayOfWeek    `json:"days_of_week"`
	// first run and end of the schedule, split into date parts
	StartYear         int  `json:"start_year"`
	StartMonth        int  `json:"start_month"`
	StartDay          int  `json:"start_day"`
	StartHour         int  `json:"start_hour"`
	StartMinute       int  `json:"start_min"`
	ExpireYear        int  `json:"expire_year"`
	ExpireMonth       int  `json:"expire_month"`
	ExpireDay         int  `json:"expire_day"`
	ExpireHour        int  `json:"expire_hour"`
	ExpireMinute      int  `json:"expire_min"`
	StopAtDurationEnd bool `json:"stop_at_duration_end"`
	// optional jitter and repetition of each run
	RandomDelay        period.Period `json:"random_delay"`
	RepetitionInterval period.Period `json:"repetition_interval"`
	RepetitionDuration period.Period `json:"repetition_duration"`
	// monthly triggers: which days, weeks and months
	DaysOfMonth         taskmaster.DayOfMonth `json:"days_of_month"`
	RunOnLastDayOfMonth bool                  `json:"run_on_last_day_of_month"`
	MonthsOfYear        taskmaster.Month      `json:"months_of_year"`
	WeeksOfMonth        taskmaster.Week       `json:"weeks_of_month"`
}

func (t SchedTask) plan() taskPlan {
	return taskPlan{
		Type: t.Type, Name: t.Name, Trigger: t.Trigger, PK: t.PK,
		Path: t.Path, WorkDir: t.WorkDir, Args: t.Args,
		DayInterval:    uint8(t.DayInterval),
		WeekInterval:   uint8(t.WeekInterval),
		DaysOfWeek:     uint16(t.DaysOfWeek),
		DaysOfMonth:    uint32(t.DaysOfMonth),
		LastDayOfMonth: t.RunOnLastDayOfMonth,
		MonthsOfYear:   uint16(t.MonthsOfYear),
		WeeksOfMonth:   uint8(t.WeeksOfMonth),
		Policy:         uint(t.TaskPolicy),
		Start:          [5]int{t.StartYear, t.StartMonth, t.StartDay, t.StartHour, t.StartMinute},
		Expire:         [5]int{t.ExpireYear, t.ExpireMonth, t.ExpireDay, t.ExpireHour, t.ExpireMinute},
		HasExpire:      t.ExpireYear != 0,
	}
}

// nil for manual tasks. Call only after plan().check() passed.
func (t SchedTask) trigger() taskmaster.Trigger {
	if t.Trigger == "manual" {
		return nil
	}
	if t.Trigger == "onboarding" {
		return taskmaster.RegistrationTrigger{
			TaskTrigger: taskmaster.TaskTrigger{Enabled: t.Enabled},
			Delay:       t.RandomDelay,
		}
	}
	p := t.plan()
	base := taskmaster.TaskTrigger{
		Enabled: t.Enabled,
		RepetitionPattern: taskmaster.RepetitionPattern{
			RepetitionInterval: t.RepetitionInterval,
			RepetitionDuration: t.RepetitionDuration,
			StopAtDurationEnd:  t.StopAtDurationEnd,
		},
	}
	base.StartBoundary, _ = localTime(p.Start)
	if p.HasExpire {
		base.EndBoundary, _ = localTime(p.Expire)
	}
	switch t.Trigger {
	case "runonce":
		return taskmaster.TimeTrigger{TaskTrigger: base, RandomDelay: t.RandomDelay}
	case "daily":
		return taskmaster.DailyTrigger{TaskTrigger: base, DayInterval: t.DayInterval, RandomDelay: t.RandomDelay}
	case "weekly":
		return taskmaster.WeeklyTrigger{TaskTrigger: base, DaysOfWeek: t.DaysOfWeek, WeekInterval: t.WeekInterval, RandomDelay: t.RandomDelay}
	case "monthly":
		return taskmaster.MonthlyTrigger{TaskTrigger: base, DaysOfMonth: t.DaysOfMonth, MonthsOfYear: t.MonthsOfYear,
			RandomDelay: t.RandomDelay, RunOnLastDayOfMonth: t.RunOnLastDayOfMonth}
	case "monthlydow":
		return taskmaster.MonthlyDOWTrigger{TaskTrigger: base, DaysOfWeek: t.DaysOfWeek, MonthsOfYear: t.MonthsOfYear,
			WeeksOfMonth: t.WeeksOfMonth, RandomDelay: t.RandomDelay}
	}
	return nil
}

// COM state belongs to the OS thread, so the goroutine stays on one thread.
// A connect that fails half way leaves the thread locked; it is discarded with
// the goroutine. Panics of the COM property helpers come back as errors.
func withTaskService(fn func(ts *taskmaster.TaskService) error) (err error) {
	runtime.LockOSThread()
	ts, err := taskmaster.Connect()
	if err != nil {
		return err
	}
	defer runtime.UnlockOSThread()
	defer ts.Disconnect()
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("task scheduler: %v", r)
		}
	}()
	return fn(&ts)
}

func (a *Agent) CreateSchedTask(st SchedTask) (bool, error) {
	p := st.plan()
	if err := p.check(); err != nil {
		a.Logger.Errorln("CreateSchedTask():", st.Name, err)
		return false, err
	}
	exe, dir, args := p.action(a.ProgramDir, os.Getenv("SYSTEMROOT"))
	created := false
	err := withTaskService(func(ts *taskmaster.TaskService) error {
		def := ts.NewTaskDefinition()
		if tr := st.trigger(); tr != nil {
			def.AddTrigger(tr)
		}
		def.AddAction(taskmaster.ExecAction{Path: exe, WorkingDir: dir, Args: args})
		def.Principal.UserID = "SYSTEM"
		def.Principal.LogonType = taskmaster.TASK_LOGON_SERVICE_ACCOUNT
		def.Principal.RunLevel = taskmaster.TASK_RUNLEVEL_HIGHEST
		s := &def.Settings
		s.AllowDemandStart = true
		s.AllowHardTerminate = true
		s.DontStartOnBatteries = false
		s.StopIfGoingOnBatteries = false
		s.WakeToRun = true
		s.Enabled = st.Enabled
		s.MultipleInstances = st.TaskPolicy
		if st.DeleteAfter {
			s.DeleteExpiredTaskAfter = "PT15M"
		}
		if st.RunASAP {
			s.StartWhenAvailable = true
		}
		task, ok, err := ts.CreateTask(`\`+st.Name, def, st.Overwrite)
		task.Release()
		created = ok
		return err
	})
	if err != nil {
		a.Logger.Errorln("CreateSchedTask():", st.Name, err)
		return false, err
	}
	return created, nil
}

// The scheduler's error text is passed through. The server treats
// "The system cannot find the file specified" as already deleted.
func DeleteSchedTask(name string) error {
	if !validTaskName(name) {
		return errors.New("invalid task name")
	}
	return withTaskService(func(ts *taskmaster.TaskService) error {
		return ts.DeleteTask(`\` + name)
	})
}

// Tasks directly in the root folder.
func rootTaskNames(ts *taskmaster.TaskService) ([]string, error) {
	tasks, err := ts.GetRegisteredTasks()
	if err != nil {
		return nil, err
	}
	defer tasks.Release()
	ret := []string{}
	for _, t := range tasks {
		if t.Path == `\`+t.Name {
			ret = append(ret, t.Name)
		}
	}
	return ret, nil
}

func ListSchedTasks() []string {
	ret := []string{}
	_ = withTaskService(func(ts *taskmaster.TaskService) error {
		names, err := rootTaskNames(ts)
		if err == nil {
			ret = names
		}
		return err
	})
	return ret
}

// The agent's own tasks, at uninstall.
func CleanupSchedTasks() {
	_ = withTaskService(func(ts *taskmaster.TaskService) error {
		names, err := rootTaskNames(ts)
		for _, n := range names {
			if strings.HasPrefix(n, IdentTaskPrefix) {
				_ = ts.DeleteTask(`\` + n)
			}
		}
		return err
	})
}
