package link

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/keys-pub/keys/request"
	"github.com/pkg/errors"
)

// TODO Normalize spaces, check a-zA-Z0-9 instead of ASCII

type reddit struct{}

// NewReddit service.
func NewReddit() Service {
	return &reddit{}
}

func (s *reddit) ID() string {
	return "reddit"
}

func (s *reddit) NormalizeURLString(name string, urs string) (string, error) {
	return basicURLString(strings.ToLower(urs))
}

func (s *reddit) ValidateURLString(name string, urs string) (string, error) {
	u, err := url.Parse(urs)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" {
		return "", errors.Errorf("invalid scheme for url %s", u)
	}
	switch u.Host {
	case "reddit.com", "old.reddit.com", "www.reddit.com":
		// OK
	default:
		return "", errors.Errorf("invalid host for url %s", u)
	}
	path := u.Path
	path = strings.TrimPrefix(path, "/")
	paths := strings.Split(path, "/")

	// URL from https://reddit.com/r/keyspubmsgs/comments/{id}/{username}/ to
	//          https://www.reddit.com/r/keyspubmsgs/comments/{id}/{username}.json

	prunedName := strings.ReplaceAll(name, "-", "")

	if len(paths) >= 5 && paths[0] == "r" && paths[1] == "keyspubmsgs" && paths[2] == "comments" && paths[4] == prunedName {
		// Request json
		ursj, err := url.Parse("https://www.reddit.com" + strings.TrimSuffix(u.Path, "/") + ".json")
		if err != nil {
			return "", err
		}
		return ursj.String(), nil
	}

	return "", errors.Errorf("invalid path %s", u.Path)
}

func (s *reddit) NormalizeName(name string) string {
	name = strings.ToLower(name)
	return name
}

func (s *reddit) ValidateName(name string) error {
	ok := isAlphaNumericWithDashUnderscore(name)
	if !ok {
		return errors.Errorf("name has an invalid character")
	}
	if len(name) > 20 {
		return errors.Errorf("reddit name is too long, it must be less than 21 characters")
	}
	return nil
}

func (s *reddit) CheckContent(name string, b []byte) ([]byte, error) {
	var posts redditPosts

	if err := json.Unmarshal(b, &posts); err != nil {
		return nil, err
	}
	logger.Debugf("Reddit unmarshaled posts: %+v", posts)
	if len(posts) == 0 {
		return nil, errors.Errorf("no posts")
	}

	if len(posts[0].Data.Children) == 0 {
		return nil, errors.Errorf("no listing children")
	}

	author := posts[0].Data.Children[0].Data.Author
	if name != strings.ToLower(author) {
		return nil, errors.Errorf("invalid author %s", author)
	}
	subreddit := posts[0].Data.Children[0].Data.Subreddit
	if "keyspubmsgs" != subreddit {
		return nil, errors.Errorf("invalid subreddit %s", subreddit)
	}
	selftext := posts[0].Data.Children[0].Data.Selftext
	return []byte(selftext), nil
}

func (s *reddit) Headers(ur *url.URL) ([]request.Header, error) {
	// Not sure if this is required anymore.
	if strings.HasSuffix(ur.Host, ".reddit.com") {
		return []request.Header{
			request.Header{Name: "Host", Value: "reddit.com"},
		}, nil
	}
	return nil, nil
}

type redditPosts []struct {
	Kind string `json:"kind"`
	Data struct {
		Modhash  string `json:"modhash"`
		Dist     int    `json:"dist"`
		Children []struct {
			Kind string `json:"kind"`
			Data struct {
				ApprovedAtUtc              interface{}   `json:"approved_at_utc"`
				Subreddit                  string        `json:"subreddit"`
				Selftext                   string        `json:"selftext"`
				UserReports                []interface{} `json:"user_reports"`
				Saved                      bool          `json:"saved"`
				ModReasonTitle             interface{}   `json:"mod_reason_title"`
				Gilded                     int           `json:"gilded"`
				Clicked                    bool          `json:"clicked"`
				Title                      string        `json:"title"`
				LinkFlairRichtext          []interface{} `json:"link_flair_richtext"`
				SubredditNamePrefixed      string        `json:"subreddit_name_prefixed"`
				Hidden                     bool          `json:"hidden"`
				Pwls                       interface{}   `json:"pwls"`
				LinkFlairCSSClass          interface{}   `json:"link_flair_css_class"`
				Downs                      int           `json:"downs"`
				ThumbnailHeight            interface{}   `json:"thumbnail_height"`
				TopAwardedType             interface{}   `json:"top_awarded_type"`
				ParentWhitelistStatus      interface{}   `json:"parent_whitelist_status"`
				HideScore                  bool          `json:"hide_score"`
				Name                       string        `json:"name"`
				Quarantine                 bool          `json:"quarantine"`
				LinkFlairTextColor         string        `json:"link_flair_text_color"`
				UpvoteRatio                float64       `json:"upvote_ratio"`
				AuthorFlairBackgroundColor interface{}   `json:"author_flair_background_color"`
				SubredditType              string        `json:"subreddit_type"`
				Ups                        int           `json:"ups"`
				TotalAwardsReceived        int           `json:"total_awards_received"`
				MediaEmbed                 struct {
				} `json:"media_embed"`
				ThumbnailWidth        interface{} `json:"thumbnail_width"`
				AuthorFlairTemplateID interface{} `json:"author_flair_template_id"`
				IsOriginalContent     bool        `json:"is_original_content"`
				AuthorFullname        string      `json:"author_fullname"`
				SecureMedia           interface{} `json:"secure_media"`
				IsRedditMediaDomain   bool        `json:"is_reddit_media_domain"`
				IsMeta                bool        `json:"is_meta"`
				Category              interface{} `json:"category"`
				SecureMediaEmbed      struct {
				} `json:"secure_media_embed"`
				LinkFlairText       interface{}   `json:"link_flair_text"`
				CanModPost          bool          `json:"can_mod_post"`
				Score               int           `json:"score"`
				ApprovedBy          interface{}   `json:"approved_by"`
				AuthorPremium       bool          `json:"author_premium"`
				Thumbnail           string        `json:"thumbnail"`
				Edited              bool          `json:"edited"`
				AuthorFlairCSSClass interface{}   `json:"author_flair_css_class"`
				AuthorFlairRichtext []interface{} `json:"author_flair_richtext"`
				Gildings            struct {
				} `json:"gildings"`
				ContentCategories        interface{}   `json:"content_categories"`
				IsSelf                   bool          `json:"is_self"`
				ModNote                  interface{}   `json:"mod_note"`
				Created                  float64       `json:"created"`
				LinkFlairType            string        `json:"link_flair_type"`
				Wls                      interface{}   `json:"wls"`
				RemovedByCategory        interface{}   `json:"removed_by_category"`
				BannedBy                 interface{}   `json:"banned_by"`
				AuthorFlairType          string        `json:"author_flair_type"`
				Domain                   string        `json:"domain"`
				AllowLiveComments        bool          `json:"allow_live_comments"`
				SelftextHTML             string        `json:"selftext_html"`
				Likes                    interface{}   `json:"likes"`
				SuggestedSort            interface{}   `json:"suggested_sort"`
				BannedAtUtc              interface{}   `json:"banned_at_utc"`
				ViewCount                interface{}   `json:"view_count"`
				Archived                 bool          `json:"archived"`
				NoFollow                 bool          `json:"no_follow"`
				IsCrosspostable          bool          `json:"is_crosspostable"`
				Pinned                   bool          `json:"pinned"`
				Over18                   bool          `json:"over_18"`
				AllAwardings             []interface{} `json:"all_awardings"`
				Awarders                 []interface{} `json:"awarders"`
				MediaOnly                bool          `json:"media_only"`
				CanGild                  bool          `json:"can_gild"`
				Spoiler                  bool          `json:"spoiler"`
				Locked                   bool          `json:"locked"`
				AuthorFlairText          interface{}   `json:"author_flair_text"`
				TreatmentTags            []interface{} `json:"treatment_tags"`
				Visited                  bool          `json:"visited"`
				RemovedBy                interface{}   `json:"removed_by"`
				NumReports               interface{}   `json:"num_reports"`
				Distinguished            interface{}   `json:"distinguished"`
				SubredditID              string        `json:"subreddit_id"`
				ModReasonBy              interface{}   `json:"mod_reason_by"`
				RemovalReason            interface{}   `json:"removal_reason"`
				LinkFlairBackgroundColor string        `json:"link_flair_background_color"`
				ID                       string        `json:"id"`
				IsRobotIndexable         bool          `json:"is_robot_indexable"`
				NumDuplicates            int           `json:"num_duplicates"`
				ReportReasons            interface{}   `json:"report_reasons"`
				Author                   string        `json:"author"`
				DiscussionType           interface{}   `json:"discussion_type"`
				NumComments              int           `json:"num_comments"`
				SendReplies              bool          `json:"send_replies"`
				Media                    interface{}   `json:"media"`
				ContestMode              bool          `json:"contest_mode"`
				AuthorPatreonFlair       bool          `json:"author_patreon_flair"`
				AuthorFlairTextColor     interface{}   `json:"author_flair_text_color"`
				Permalink                string        `json:"permalink"`
				WhitelistStatus          interface{}   `json:"whitelist_status"`
				Stickied                 bool          `json:"stickied"`
				URL                      string        `json:"url"`
				SubredditSubscribers     int           `json:"subreddit_subscribers"`
				CreatedUtc               float64       `json:"created_utc"`
				NumCrossposts            int           `json:"num_crossposts"`
				ModReports               []interface{} `json:"mod_reports"`
				IsVideo                  bool          `json:"is_video"`
			} `json:"data"`
		} `json:"children"`
		After  interface{} `json:"after"`
		Before interface{} `json:"before"`
	} `json:"data"`
}
