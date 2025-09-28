package main

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"log"
	"math/rand"
	"os"
	"slices"
	"time"

	"github.com/golang/freetype"
	"golang.org/x/image/font"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

var l = log.New(os.Stdout, "[koth2] ", 2)

func requestTick(ws *websocket.Conn) {
	submitMsg := &Inputs{
		Kind: &Inputs_RequestTick{RequestTick: &RequestTickInput{}},
	}
	data, _ := proto.Marshal(submitMsg)
	ws.WriteMessage(websocket.BinaryMessage, data)
}

type Bid struct {
	x     uint32
	y     uint32
	coins uint32
}

func bidsContain(bs []Bid, x uint32, y uint32) bool {
	for _, bid := range bs {
		if bid.x == x && bid.y == y {
			return true
		}
	}
	return false
}

func visualizePixels(tick uint64, tickMillis int64, pixelState [][]byte, pixelBids [][]uint32) {
	// Map pixelState -> color (for 11–20)
	colors := map[byte]color.RGBA{
		11: {255, 0, 0, 255},     // red
		12: {0, 255, 0, 255},     // green
		13: {0, 0, 255, 255},     // blue
		14: {255, 255, 0, 255},   // yellow
		15: {0, 255, 255, 255},   // cyan
		16: {255, 0, 255, 255},   // magenta
		17: {128, 0, 255, 255},   // purple
		18: {255, 165, 0, 255},   // orange
		19: {128, 128, 128, 255}, // gray
		20: {255, 255, 255, 255}, // white
	}

	cellSize := 50
	img := image.NewRGBA(image.Rect(0, 0, 10*cellSize, 10*cellSize))

	// Draw colored pixels
	for y := 0; y < 10; y++ {
		for x := 0; x < 10; x++ {
			state := pixelState[y][x]
			c, ok := colors[state]
			if !ok {
				c = color.RGBA{0, 0, 0, 255} // default black if out of range
			}
			r := image.Rect(x*cellSize, y*cellSize, (x+1)*cellSize, (y+1)*cellSize)
			draw.Draw(img, r, &image.Uniform{C: c}, image.Point{}, draw.Src)
		}
	}

	// Load font
	fontBytes, err := os.ReadFile("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")
	if err != nil {
		log.Fatalf("error loading font: %v", err)
	}
	ft, err := freetype.ParseFont(fontBytes)
	if err != nil {
		log.Fatalf("error parsing font: %v", err)
	}
	c := freetype.NewContext()
	c.SetFont(ft)
	c.SetDPI(72)
	c.SetFontSize(16)
	c.SetClip(img.Bounds())
	c.SetDst(img)
	c.SetSrc(image.Black)
	c.SetHinting(font.HintingFull)

	// Draw pixelBids as text
	for y := 0; y < 10; y++ {
		for x := 0; x < 10; x++ {
			if pixelBids[y][x] == 0 {
				continue
			}
			pt := freetype.Pt(x*cellSize+10, y*cellSize+30)
			_, err = c.DrawString(fmt.Sprintf("%d", pixelBids[y][x]), pt)
			if err != nil {
				log.Printf("error drawing text: %v", err)
			}
		}
	}

	// Save to file
	filename := fmt.Sprintf("pixels_tick%06d_sub%03d.png", tick, tickMillis)
	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	png.Encode(f, img)
}

func main() {
	l.SetFlags(log.LstdFlags | log.Lmicroseconds)

	uri := "ws://game.k.challs.mt:3030/ws"
	ws, _, err := websocket.DefaultDialer.Dial(uri, nil)
	if err != nil {
		l.Fatal("dial:", err)
	}
	defer ws.Close()

	authMsg := &Inputs{
		Kind: &Inputs_Auth{Auth: &AuthInput{Token: "a4b5f4d8-72a3-4d30-8eb4-8293a4b5c6d7"}},
	}
	data, _ := proto.Marshal(authMsg)
	err = ws.WriteMessage(websocket.BinaryMessage, data)
	if err != nil {
		l.Fatal("write:", err)
	}

	var prevResp *TickOutput
	bidId := 0
	bidRecvId := 0
	mslcCoins := uint32(0)
	//tickStart := time.Now()
	pixelState := make([][]byte, 10)
	pixelBids := make([][]uint32, 10)
	for i := 0; i < 10; i++ {
		pixelState[i] = make([]byte, 10)
		pixelBids[i] = make([]uint32, 10)
	}
	teamPixels := make(map[int]int) // team id -> #pixels
	maxPixelsPerTickReached := false
	t0Points := 0
	t0 := time.Now()
	for {
		mt, message, err := ws.ReadMessage()
		if err != nil {
			l.Fatal("read:", err)
		}

		if mt == websocket.TextMessage {
			ms := string(message)
			if ms == "submit" {
				l.Printf("OK id=%d\n", bidRecvId)
				bidRecvId += 1
			} else if ms == "error: max pixels per tick reached" {
				l.Printf("MAX id=%d\n", bidRecvId)
				bidRecvId += 1
				maxPixelsPerTickReached = true
			} else if ms == "error: bid must be > current" {
				l.Printf("CUR id=%d\n", bidRecvId)
				bidRecvId += 1
			} else if ms == "error: insufficient coins" {
				l.Printf("COIN id=%d\n", bidRecvId)
				bidRecvId += 1
			} else {
				l.Println("ms:", ms)
			}
			continue
		}

		resp := &TickOutput{}
		err = proto.Unmarshal(message, resp)
		if err != nil {
			l.Fatal("unmarshal:", err)
		}
		requestTick(ws)
		changed := true
		if prevResp == nil || resp.TickNumber != prevResp.TickNumber {
			l.Printf("Tick: %d, unspent coins: %d\n", resp.TickNumber, mslcCoins)
			prevResp = resp
			//tickStart = time.Now()
			maxPixelsPerTickReached = false
			// team idx = team id - 1
			l.Printf("Tick results:\n")
			for teamId, nPixels := range teamPixels {
				l.Printf("  %s (idx=%d) pixels=%d\n", resp.TeamNames[teamId-1], teamId-1, nPixels)
			}
		} else {
			changed = !slices.Equal(prevResp.PixelState, resp.PixelState) || !slices.Equal(prevResp.PixelBids, resp.PixelBids)
		}

		// team name -> team index
		teams := make(map[string]int)
		for idx, name := range resp.TeamNames {
			if name == "" {
				continue
			}
			teams[name] = int(idx)
		}
		mslcIdx := teams["mslc"]
		if t0Points == 0 {
			t0Points = int(resp.TeamPoints[mslcIdx])
			t0 = time.Now()
		} else {
			dt := int(time.Now().Sub(t0).Seconds())
			if dt != 0 {
				speed := (int(resp.TeamPoints[mslcIdx]) - t0Points) / dt
				l.Printf("speed=%d, dt=%d\n", speed, dt)
			}
		}

		// unflatten
		teamPixels = make(map[int]int)
		claimCount := 0
		claimedPixelCount := 0
		for y := 0; y < 10; y++ {
			for x := 0; x < 10; x++ {
				idx := y*10 + x
				pixelState[y][x] = resp.PixelState[idx]
				pixelBids[y][x] = resp.PixelBids[idx]
				claimCount += int(pixelBids[y][x])
				if pixelBids[y][x] != 0 {
					claimedPixelCount += 1
				}
				teamPixels[int(pixelState[y][x])]++
			}
		}
		if changed {
			//	visualizePixels(resp.TickNumber, time.Now().Sub(tickStart).Milliseconds(), pixelState, pixelBids)
		}

		richestTeamIdx := uint32(0)
		richestTeamWeight := 0
		for teamIdx, points := range resp.TeamPoints {
			if teamIdx == mslcIdx {
				continue
			}
			weight := int(points) /*+ teamPixels[teamIdx-1]*10000*/
			if weight > richestTeamWeight {
				richestTeamWeight = weight
				richestTeamIdx = uint32(teamIdx)
			}
		}

		l.Printf("richest team is %s (%d) with weight %d\n",
			resp.TeamNames[richestTeamIdx], richestTeamIdx, richestTeamWeight)
		l.Println("pixelState:", pixelState)
		l.Println("pixelBids:", pixelBids)
		mslcCoins = resp.TeamCoins[mslcIdx]
		l.Println("mslcCoins:", mslcCoins)
		l.Println("claimCount:", claimCount)
		l.Println("claimedPixelCount:", claimedPixelCount)

		// Determine pixels to bid on
		var attack1Pixels, eatTheRichPixels, berserkPixels [][2]uint32
		for y := uint32(0); y < 10; y++ {
			for x := uint32(0); x < 10; x++ {
				if int(pixelState[y][x])-1 != mslcIdx && pixelBids[y][x] == 1 {
					attack1Pixels = append(attack1Pixels, [2]uint32{x, y})
				} else if uint32(pixelState[y][x])-1 == richestTeamIdx && pixelBids[y][x] == 0 {
					eatTheRichPixels = append(eatTheRichPixels, [2]uint32{x, y})
				} else if int(pixelState[y][x])-1 != mslcIdx && pixelBids[y][x] == 0 {
					berserkPixels = append(berserkPixels, [2]uint32{x, y})
				}
			}
		}
		l.Printf("attack1Pixels=%s\n", attack1Pixels)
		l.Printf("eatTheRichPixels=%s\n", eatTheRichPixels)
		l.Printf("berserkPixels=%s\n", berserkPixels)

		var bids []Bid
		nAttack1Pixels := 0
		nEatTheRich := 0
		nBerserk := 0
		if false && maxPixelsPerTickReached {
			nAttack1Pixels = min(int(mslcCoins)/2, len(attack1Pixels))
		} else {
			nEatTheRich = min(int(mslcCoins), len(eatTheRichPixels))
			nBerserk = min(int(mslcCoins)-nEatTheRich, len(berserkPixels))
		}
		for i := 0; i < nAttack1Pixels; i++ {
			for {
				pxl := attack1Pixels[rand.Intn(len(attack1Pixels))]
				if !bidsContain(bids, pxl[0], pxl[1]) {
					bids = append(bids, Bid{x: pxl[0], y: pxl[1], coins: 2})
					break
				}
			}
		}
		for i := 0; i < nEatTheRich; i++ {
			for {
				pxl := eatTheRichPixels[rand.Intn(len(eatTheRichPixels))]
				if !bidsContain(bids, pxl[0], pxl[1]) {
					bids = append(bids, Bid{x: pxl[0], y: pxl[1], coins: 1})
					break
				}
			}
		}
		for i := 0; i < nBerserk; i++ {
			for {
				pxl := berserkPixels[rand.Intn(len(berserkPixels))]
				if !bidsContain(bids, pxl[0], pxl[1]) {
					bids = append(bids, Bid{x: pxl[0], y: pxl[1], coins: 1})
					break
				}
			}
		}

		if bidId < bidRecvId+20 {
			for _, bid := range bids {
				bidStr := fmt.Sprintf("id=%d x=%d y=%d coins=%d", bidId, bid.x, bid.y, bid.coins)
				bidId += 1
				l.Printf("bidding on tick %d: %s\n", resp.TickNumber, bidStr)
				submitMsg := &Inputs{
					Kind: &Inputs_Submit{Submit: &SubmitInput{X: bid.x, Y: bid.y, Coins: bid.coins}},
				}
				data, _ := proto.Marshal(submitMsg)
				ws.WriteMessage(websocket.BinaryMessage, data)
			}
		}

	}
}
