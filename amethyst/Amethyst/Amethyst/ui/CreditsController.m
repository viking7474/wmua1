#import "../AppDelegate.h"
#import "Utilities.h"
#import "CreditsController.h"

#define addCredit(name, _detail, link) [[CreditsInfo alloc] init:@name detail:@_detail linkUrl:@link]

@implementation CreditsInfo
- (id)init:(NSString *)name detail:(NSString *)detail linkUrl:(NSString *)linkUrl {
    self = [super init];
    self.userName = name;
    self.userDetail = detail;
    self.linkUrl = linkUrl;
    return self;
}
@end

@implementation CreditsController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.tableData = @[
        addCredit("staturnz", "Main Developer", "https://github.com/staturnzz"),
        addCredit("Alfie CG", "Trigon", "https://github.com/alfiecg24"),
        addCredit("Clarity", "Various techniques", "https://github.com/TheRealClarity"),
        addCredit("xerus", "Logo, Icon, Designs", "https://x.com/xerusdesign"),
        addCredit("felix-pb", "puaf_physpuppet", "https://github.com/felix-pb"),
        addCredit("opa334", "Various techniques", "https://github.com/opa334"),
        addCredit("xerub", "Patchfinder base", "https://github.com/xerub"),
        addCredit("oct0xor", "Operation Triangulation", "https://github.com/oct0xor"),
        addCredit("kucher1n", "Operation Triangulation", "https://x.com/kucher1n"),
        addCredit("bzvr_", "Operation Triangulation", "https://x.com/bzvr_"),
        addCredit("Procursus", "Bootstrap", "https://github.com/ProcursusTeam"),
        addCredit("Zebra Team", "Zebra", "https://github.com/zbrateam"),
        addCredit("Sileo Team", "Sileo", "https://github.com/Sileo")
    ];
    
    self.view.translatesAutoresizingMaskIntoConstraints = NO;
    self.view.backgroundColor = [UIColor clearColor];
    self.tableView.allowsMultipleSelection = NO;
    self.tableView.rowHeight = 50.0f;
    self.tableView.showsVerticalScrollIndicator = NO;
    self.tableView.separatorColor = [[UIColor whiteColor] colorWithAlphaComponent:0.1];
    self.tableView.separatorInset = UIEdgeInsetsMake(0, 20, 0, 20);
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.tableData.count;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    CreditsInfo *creditsInfo = self.tableData[indexPath.row];
    if ([creditsInfo.linkUrl isEqualToString:@""]) return;
    NSURL *linkUrl = [NSURL URLWithString:creditsInfo.linkUrl];
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    [[UIApplication sharedApplication] openURL:linkUrl options:@{} completionHandler:NULL];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"creditCell"];
    if (cell == NULL) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"creditCell"];
    
    CreditsInfo *creditsInfo = self.tableData[indexPath.row];
    cell.textLabel.text = creditsInfo.userName;
    cell.detailTextLabel.text = creditsInfo.userDetail;
    cell.backgroundColor = [UIColor clearColor];
    cell.detailTextLabel.textColor = [[UIColor whiteColor] colorWithAlphaComponent:0.75];
    cell.textLabel.textColor = [[UIColor whiteColor] colorWithAlphaComponent:0.95];

    UIView *selectedView = [[UIView alloc] init];
    selectedView.layer.cornerRadius = 15;
    selectedView.layer.masksToBounds = YES;
    selectedView.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.2f];
    [cell setSelectedBackgroundView:selectedView];
    return cell;
}
@end
