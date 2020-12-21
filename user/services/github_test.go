package services_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/user"
	"github.com/keys-pub/keys/user/services"
	"github.com/stretchr/testify/require"
)

func TestGithub(t *testing.T) {
	// user.SetLogger(user.NewLogger(user.DebugLevel))
	// services.SetLogger(user.NewLogger(user.DebugLevel))

	kid := keys.ID("kex1mnseg28xu6g3j4wur7hqwk8ag3fu3pmr2t5lync26xmgff0dtryqupf80c")
	urs := "https://gist.github.com/gabriel/ceea0f3b675bac03425472692273cf52"

	client := http.NewClient()

	usr, err := user.New(kid, "github", "gabriel", urs, 1)
	require.NoError(t, err)
	result := services.Verify(context.TODO(), services.Github, client, usr)
	require.Equal(t, user.StatusOK, result.Status)
	expected := `BEGIN MESSAGE.
kdZaJI1U5AS7G6i VoUxdP8OtPzEoM6 pYhVl0YQZJnotVE wLg9BDb5SUO05pm
abUSeCvBfdPoRpP J8wrcF5PP3wTCKq 6Xr2MZHgg6m2Qal gJCD6vMqlBQfIg6
QsfB27aP5DMuXlJ AUVIAvMDHIoptmS riNMzfpwBjRShVL WH70a0GOEqD6L8b
kC5EFOwCedvHFpc AQVqULHjcSpeCfZ EIOaQ2IP.
END MESSAGE.`
	require.Equal(t, expected, result.Statement)
}

func TestGithubKeysPubUser(t *testing.T) {
	// user.SetLogger(user.NewLogger(user.DebugLevel))
	// services.SetLogger(user.NewLogger(user.DebugLevel))

	kid := keys.ID("kex1ncfla8g5ez6vfq3trj9vpsdswqlv9fcqdks6x86nt0j7yljk3d8supvfj7")
	urs := "https://gist.github.com/keys-pub-user/63965d96e6586ee7e3ec3530e4331982"

	client := http.NewClient()

	usr, err := user.New(kid, "github", "keys-pub-user", urs, 1)
	require.NoError(t, err)
	result := services.Verify(context.TODO(), services.Github, client, usr)
	require.Equal(t, user.StatusOK, result.Status)
	expected := `BEGIN MESSAGE.
tFOTGkqFiM1YL3P lG4V0DzFi95jz1A VaOn0e5KzZ5wzFq D2LanZPiN928o3M
jPUOV3KlEcDr0iV Y6R2GYtcP2WTCKq 6Xr2MZHgg6oMjst MtVs8AxBTgCn0ed
yNy78Ob23NoqDTi HLaHzAYYHCLYA3H hpW04H2qOcy9wUT TbzbvuqS4jIXVCm
WgBpeqxaDOC8tGL 2rHKnD6KhZrBw8d tSPCc8sSTVh227E D.
END MESSAGE.`
	require.Equal(t, expected, result.Statement)
}
