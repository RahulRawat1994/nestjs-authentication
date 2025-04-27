import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class AccessTokenBlacklist {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true, nullable: false })
  token: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  blacklisted_at: Date;
}
