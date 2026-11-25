//! 画托盘图标：盾牌加一条心电波形，按托盘实际需要的尺寸逐像素画出来。
//!
//! 不缩放 EXE 里的图标：小尺寸要单独调线宽才看得清，动画帧也要能改波形的亮度。
//! 坐标以图标边长为 1，y 轴向下。输出是自上而下的 BGRA 行，alpha 不预乘，
//! `CreateIconIndirect` 要的就是这种格式。

/// 盾牌轮廓：顶尖、右肩、右腰、底尖、左腰、左肩。
const SHIELD: [(f32, f32); 6] = [
    (0.5, 0.03),
    (0.93, 0.18),
    (0.93, 0.52),
    (0.5, 0.97),
    (0.07, 0.52),
    (0.07, 0.18),
];
/// 心电波形：平、上冲、下冲、回到基线。
const PULSE: [(f32, f32); 6] = [
    (0.17, 0.47),
    (0.37, 0.47),
    (0.47, 0.25),
    (0.60, 0.69),
    (0.68, 0.47),
    (0.83, 0.47),
];
/// 没有信号时的一条平线。
const FLAT: [(f32, f32); 2] = [(0.17, 0.47), (0.83, 0.47)];
const LINE_COLOR: u32 = 0xffffff;
/// 每个像素在每个方向上的采样数，用来抗锯齿。
const SAMPLES: usize = 4;

/// 动画一圈的帧数。
pub(crate) const SWEEP_FRAMES: usize = 16;
/// 亮段的长度，占整条波形的比例。
const SWEEP_TAIL: f32 = 0.5;
/// 亮段以外的波形亮度。
const SWEEP_BASE: f32 = 0.3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Line {
    Pulse,
    Flat,
}

/// 波形怎么画：整条都亮，或者动画第几帧（一道亮光从左往右扫过）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shine {
    Full,
    Sweep(usize),
}

impl Shine {
    /// 波形上某一点的亮度；`at` 是这一点在波形上的位置，0 是左端，1 是右端。
    fn alpha(self, at: f32) -> f32 {
        match self {
            Self::Full => 1.,
            Self::Sweep(frame) => {
                let head = (frame % SWEEP_FRAMES) as f32 / SWEEP_FRAMES as f32 * (1. + SWEEP_TAIL);
                let behind = head - at;
                if (0. ..=SWEEP_TAIL).contains(&behind) {
                    SWEEP_BASE + (1. - SWEEP_BASE) * (1. - behind / SWEEP_TAIL)
                } else {
                    SWEEP_BASE
                }
            }
        }
    }
}

/// 一段折线，带它的起点在整条线上的位置。
struct Segment {
    from: (f32, f32),
    to: (f32, f32),
    start: f32,
    length: f32,
}

fn segments(points: &[(f32, f32)]) -> (Vec<Segment>, f32) {
    let mut start = 0.;
    let segments = points
        .windows(2)
        .map(|pair| {
            let length = (pair[1].0 - pair[0].0).hypot(pair[1].1 - pair[0].1);
            let segment = Segment {
                from: pair[0],
                to: pair[1],
                start,
                length,
            };
            start += length;
            segment
        })
        .collect();
    (segments, start)
}

/// 点到折线的最近距离，以及最近点在线上的位置（0 到 1）。
fn nearest(segments: &[Segment], total: f32, x: f32, y: f32) -> (f32, f32) {
    let mut best = (f32::INFINITY, 0.);
    for segment in segments {
        let (dx, dy) = (segment.to.0 - segment.from.0, segment.to.1 - segment.from.1);
        let along = (((x - segment.from.0) * dx + (y - segment.from.1) * dy)
            / (segment.length * segment.length))
            .clamp(0., 1.);
        let distance = (x - segment.from.0 - along * dx).hypot(y - segment.from.1 - along * dy);
        if distance < best.0 {
            best = (distance, (segment.start + along * segment.length) / total);
        }
    }
    best
}

fn inside_shield(x: f32, y: f32) -> bool {
    let mut inside = false;
    for (index, &(x1, y1)) in SHIELD.iter().enumerate() {
        let (x2, y2) = SHIELD[(index + 1) % SHIELD.len()];
        if (y1 > y) != (y2 > y) && x < (x2 - x1) * (y - y1) / (y2 - y1) + x1 {
            inside = !inside;
        }
    }
    inside
}

fn channels(color: u32) -> [f32; 3] {
    [
        ((color >> 16) & 0xff) as f32,
        ((color >> 8) & 0xff) as f32,
        (color & 0xff) as f32,
    ]
}

/// 画一帧，返回 `size * size` 个像素的 BGRA 字节，自上而下逐行排列。
/// `fill` 是盾牌的颜色（0xRRGGBB），波形是白色。
pub(crate) fn render(size: usize, fill: u32, line: Line, shine: Shine) -> Vec<u8> {
    let points: &[(f32, f32)] = match line {
        Line::Pulse => &PULSE,
        Line::Flat => &FLAT,
    };
    let (segments, total) = segments(points);
    let scale = size.max(1) as f32;
    // 16px 时线宽约 1.8 像素：再细就成了时有时无的灰线。
    let half_width = (1.7 / scale).max(0.115) / 2.;
    let fill = channels(fill);
    let white = channels(LINE_COLOR);
    let mut pixels = Vec::with_capacity(size * size * 4);
    for row in 0..size {
        for column in 0..size {
            let mut sum = [0f32; 3];
            let mut covered = 0usize;
            for sub_row in 0..SAMPLES {
                for sub_column in 0..SAMPLES {
                    let x = (column as f32 + (sub_column as f32 + 0.5) / SAMPLES as f32) / scale;
                    let y = (row as f32 + (sub_row as f32 + 0.5) / SAMPLES as f32) / scale;
                    if !inside_shield(x, y) {
                        continue;
                    }
                    let (distance, at) = nearest(&segments, total, x, y);
                    let mix = if distance <= half_width {
                        shine.alpha(at)
                    } else {
                        0.
                    };
                    for channel in 0..3 {
                        sum[channel] += fill[channel] * (1. - mix) + white[channel] * mix;
                    }
                    covered += 1;
                }
            }
            if covered == 0 {
                pixels.extend([0, 0, 0, 0]);
                continue;
            }
            let average = |channel: usize| (sum[channel] / covered as f32).round() as u8;
            let alpha = (covered * 255 + SAMPLES * SAMPLES / 2) / (SAMPLES * SAMPLES);
            pixels.extend([average(2), average(1), average(0), alpha as u8]);
        }
    }
    pixels
}

#[cfg(test)]
mod tests {
    use super::*;

    const GREEN: u32 = 0x1f9d50;

    fn pixel(pixels: &[u8], size: usize, x: usize, y: usize) -> [u8; 4] {
        let offset = (y * size + x) * 4;
        pixels[offset..offset + 4].try_into().expect("four bytes")
    }

    #[test]
    fn every_size_yields_one_bgra_pixel_per_cell() {
        for size in [16, 20, 24, 32, 40, 48, 64] {
            assert_eq!(
                render(size, GREEN, Line::Pulse, Shine::Full).len(),
                size * size * 4
            );
        }
        assert!(render(0, GREEN, Line::Pulse, Shine::Full).is_empty());
    }

    #[test]
    fn corners_are_transparent_and_the_shield_is_opaque_fill() {
        let size = 32;
        let pixels = render(size, GREEN, Line::Pulse, Shine::Full);
        for (x, y) in [(0, 0), (31, 0), (0, 31), (31, 31)] {
            assert_eq!(pixel(&pixels, size, x, y)[3], 0, "({x}, {y})");
        }
        // 盾牌上半部、波形上方：纯底色，BGRA 顺序。
        assert_eq!(pixel(&pixels, size, 16, 5), [0x50, 0x9d, 0x1f, 255]);
    }

    #[test]
    fn the_line_is_white_at_full_shine_and_dim_away_from_the_sweep() {
        let size = 32;
        // 左端基线上的一点。
        let (x, y) = (7, 15);
        let full = render(size, GREEN, Line::Pulse, Shine::Full);
        assert_eq!(pixel(&full, size, x, y), [255, 255, 255, 255]);
        // 最后一帧亮段已经扫到右端，左端只剩底亮度。
        let dim = render(size, GREEN, Line::Pulse, Shine::Sweep(SWEEP_FRAMES - 1));
        let [blue, green, red, alpha] = pixel(&dim, size, x, y);
        assert_eq!(alpha, 255);
        assert!(
            red < 120 && green < 210 && blue < 150,
            "{red} {green} {blue}"
        );
    }

    #[test]
    fn each_sweep_frame_differs_from_the_previous_one() {
        let frames: Vec<_> = (0..SWEEP_FRAMES)
            .map(|frame| render(16, GREEN, Line::Pulse, Shine::Sweep(frame)))
            .collect();
        for pair in frames.windows(2) {
            assert_ne!(pair[0], pair[1]);
        }
        assert_eq!(
            render(16, GREEN, Line::Pulse, Shine::Sweep(SWEEP_FRAMES)),
            frames[0]
        );
    }

    #[test]
    fn the_flat_line_has_no_peaks() {
        let size = 32;
        let pulse = render(size, GREEN, Line::Pulse, Shine::Full);
        let flat = render(size, GREEN, Line::Flat, Shine::Full);
        // 波形的上冲尖附近：脉冲是白线，平线时是底色。
        let peak = (15, 9);
        assert_eq!(pixel(&pulse, size, peak.0, peak.1)[0], 255);
        assert_eq!(pixel(&flat, size, peak.0, peak.1), [0x50, 0x9d, 0x1f, 255]);
    }
}
