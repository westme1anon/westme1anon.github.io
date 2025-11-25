// 友情链接数据配置
// 用于管理友情链接页面的数据

export interface FriendItem {
	id: number;
	title: string;
	imgurl: string;
	desc: string;
	siteurl: string;
	tags: string[];
}

// 友情链接数据
export const friendsData: FriendItem[] = [
	{
		id: 1,
		title: "Artino1's Blog",
		imgurl: "https://atrino1.github.io/img/avater.jpg",
		desc: "Re fresher",
		siteurl: "https://atrino1.github.io",
		tags: ["ctfer"],
	},
	{
		id: 2,
		title: "Nick's Blog",
		imgurl:
			"https://nickchen.top/avatar.jpg",
		desc: "越平静，越汹涌",
		siteurl: "https://nickchen.top/",
		tags: ["ctfer"],
	},
	{
		id: 3,
		title: "JSnow's Blog",
		imgurl: "https://j5now.github.io/img/me.jpg",
		desc: "梦想成为游戏逆向高手",
		siteurl: "https://j5now.github.io/",
		tags: ["ctfer"],
	},
	{
		id: 4,
		title: "wuye's Blog",
		imgurl: "https://www.mgoyy.cn/images/b0c1d74766dd8bce0ad860be15c46993a.jpg",
		desc: "无夜的逆向之旅",
		siteurl: "https://changye123456.github.io",
		tags: ["ctfer"],
	},
];

// 获取所有友情链接数据
export function getFriendsList(): FriendItem[] {
	return friendsData;
}

// 获取随机排序的友情链接数据
export function getShuffledFriendsList(): FriendItem[] {
	const shuffled = [...friendsData];
	for (let i = shuffled.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
	}
	return shuffled;
}
