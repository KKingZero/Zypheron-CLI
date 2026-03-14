package scheduler

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseCronExpression parses a cron expression and returns the next run time
// Supports basic cron format: "minute hour day month weekday"
// Examples:
//   - "0 2 * * *"     - Every day at 2:00 AM
//   - "*/15 * * * *"  - Every 15 minutes
//   - "0 0 * * 0"     - Every Sunday at midnight
//   - "30 3 1 * *"    - First day of every month at 3:30 AM
func ParseCronExpression(expr string, from time.Time) (time.Time, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return time.Time{}, fmt.Errorf("invalid cron expression: expected 5 fields, got %d", len(fields))
	}

	// Parse fields
	minute, err := parseField(fields[0], 0, 59)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid minute field: %w", err)
	}

	hour, err := parseField(fields[1], 0, 23)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid hour field: %w", err)
	}

	day, err := parseField(fields[2], 1, 31)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid day field: %w", err)
	}

	month, err := parseField(fields[3], 1, 12)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid month field: %w", err)
	}

	weekday, err := parseField(fields[4], 0, 6)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid weekday field: %w", err)
	}

	// Calculate next run time
	next := from.Add(time.Minute)
	next = time.Date(next.Year(), next.Month(), next.Day(), next.Hour(), next.Minute(), 0, 0, next.Location())

	// Find the next matching time (with a reasonable limit to prevent infinite loops)
	maxIterations := 525600 // One year worth of minutes
	for i := 0; i < maxIterations; i++ {
		if matches(next, minute, hour, day, month, weekday) {
			return next, nil
		}
		next = next.Add(time.Minute)
	}

	return time.Time{}, fmt.Errorf("could not find next run time within one year")
}

// cronField represents a parsed cron field
type cronField struct {
	all      bool
	values   []int
	step     int
	hasStep  bool
	rangeMin int
	rangeMax int
}

// parseField parses a single cron field
func parseField(field string, min, max int) (cronField, error) {
	cf := cronField{}

	// Handle wildcard
	if field == "*" {
		cf.all = true
		return cf, nil
	}

	// Handle step values (*/n)
	if strings.Contains(field, "/") {
		parts := strings.Split(field, "/")
		if len(parts) != 2 {
			return cf, fmt.Errorf("invalid step format")
		}

		step, err := strconv.Atoi(parts[1])
		if err != nil {
			return cf, fmt.Errorf("invalid step value: %w", err)
		}

		if step <= 0 {
			return cf, fmt.Errorf("step value must be positive")
		}

		cf.hasStep = true
		cf.step = step

		if parts[0] == "*" {
			cf.all = true
			return cf, nil
		}

		// Parse range for step
		rangeField, err := parseField(parts[0], min, max)
		if err != nil {
			return cf, err
		}
		cf.rangeMin = rangeField.rangeMin
		cf.rangeMax = rangeField.rangeMax
		return cf, nil
	}

	// Handle ranges (n-m)
	if strings.Contains(field, "-") {
		parts := strings.Split(field, "-")
		if len(parts) != 2 {
			return cf, fmt.Errorf("invalid range format")
		}

		rangeMin, err := strconv.Atoi(parts[0])
		if err != nil {
			return cf, fmt.Errorf("invalid range start: %w", err)
		}

		rangeMax, err := strconv.Atoi(parts[1])
		if err != nil {
			return cf, fmt.Errorf("invalid range end: %w", err)
		}

		if rangeMin < min || rangeMin > max || rangeMax < min || rangeMax > max {
			return cf, fmt.Errorf("range values must be between %d and %d", min, max)
		}

		if rangeMin > rangeMax {
			return cf, fmt.Errorf("range start must be less than or equal to range end")
		}

		cf.rangeMin = rangeMin
		cf.rangeMax = rangeMax
		for i := rangeMin; i <= rangeMax; i++ {
			cf.values = append(cf.values, i)
		}
		return cf, nil
	}

	// Handle comma-separated values (n,m,o)
	if strings.Contains(field, ",") {
		parts := strings.Split(field, ",")
		for _, part := range parts {
			val, err := strconv.Atoi(part)
			if err != nil {
				return cf, fmt.Errorf("invalid value: %w", err)
			}
			if val < min || val > max {
				return cf, fmt.Errorf("value must be between %d and %d", min, max)
			}
			cf.values = append(cf.values, val)
		}
		return cf, nil
	}

	// Handle single value
	val, err := strconv.Atoi(field)
	if err != nil {
		return cf, fmt.Errorf("invalid value: %w", err)
	}
	if val < min || val > max {
		return cf, fmt.Errorf("value must be between %d and %d", min, max)
	}
	cf.values = []int{val}
	return cf, nil
}

// matches checks if the given time matches all cron fields
func matches(t time.Time, minute, hour, day, month, weekday cronField) bool {
	if !matchField(minute, t.Minute()) {
		return false
	}
	if !matchField(hour, t.Hour()) {
		return false
	}
	if !matchField(day, t.Day()) {
		return false
	}
	if !matchField(month, int(t.Month())) {
		return false
	}
	if !matchField(weekday, int(t.Weekday())) {
		return false
	}
	return true
}

// matchField checks if a value matches a cron field
func matchField(field cronField, value int) bool {
	// Wildcard matches everything
	if field.all {
		if field.hasStep {
			return value%field.step == 0
		}
		return true
	}

	// Check step
	if field.hasStep {
		if field.rangeMin != 0 || field.rangeMax != 0 {
			if value < field.rangeMin || value > field.rangeMax {
				return false
			}
			return (value-field.rangeMin)%field.step == 0
		}
		return value%field.step == 0
	}

	// Check explicit values
	for _, v := range field.values {
		if v == value {
			return true
		}
	}
	return false
}

// ValidateCronExpression validates a cron expression without calculating next run
func ValidateCronExpression(expr string) error {
	_, err := ParseCronExpression(expr, time.Now())
	return err
}

// GetCronDescription returns a human-readable description of a cron expression
func GetCronDescription(expr string) string {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return "Invalid cron expression"
	}

	// Common patterns
	if expr == "* * * * *" {
		return "Every minute"
	}
	if expr == "0 * * * *" {
		return "Every hour"
	}
	if expr == "0 0 * * *" {
		return "Every day at midnight"
	}
	if expr == "0 0 * * 0" {
		return "Every Sunday at midnight"
	}
	if expr == "0 0 1 * *" {
		return "First day of every month at midnight"
	}

	// Build description
	desc := "At "

	// Minute
	if fields[0] == "*" {
		desc += "every minute"
	} else if strings.Contains(fields[0], "/") {
		step := strings.Split(fields[0], "/")[1]
		desc += "every " + step + " minutes"
	} else {
		desc += "minute " + fields[0]
	}

	// Hour
	if fields[1] != "*" {
		desc += " past hour " + fields[1]
	}

	// Day
	if fields[2] != "*" {
		desc += " on day " + fields[2]
	}

	// Month
	if fields[3] != "*" {
		monthNames := []string{"", "January", "February", "March", "April", "May", "June",
			"July", "August", "September", "October", "November", "December"}
		month, _ := strconv.Atoi(fields[3])
		if month > 0 && month < 13 {
			desc += " in " + monthNames[month]
		}
	}

	// Weekday
	if fields[4] != "*" {
		dayNames := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
		day, _ := strconv.Atoi(fields[4])
		if day >= 0 && day < 7 {
			desc += " on " + dayNames[day]
		}
	}

	return desc
}
